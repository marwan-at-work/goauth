package goauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	"golang.org/x/oauth2"
	"marwan.io/goauth/jws"
)

// publicKeysURL is the known URL where google public keys
// are stored and rotated
const publicKeysURL = "https://www.googleapis.com/oauth2/v3/certs"

// Authenticator is a middleware and a verifier
// for authenticating against your gmail account.
type Authenticator struct {
	// Config is the required client credentials configuraiton
	Config *oauth2.Config
	// OauthPath is the required oauth callback path.
	OauthPath string
	// SkipFunc for paths that skip authentication
	SkipFunc func(r *http.Request) bool
	// CookieNmae is the cookie that gets sent to the client
	CookieName string
	// Whether to set "secure" on the cookie value or not
	SecureCookie bool
	// CookieDomain is the required domain value
	// for the cookie header.
	CookieDomain string
	// VerifyFunc is the required function that a caller
	// supplies to verify that a user is allowed to access
	// the http endpoint.
	VerifyFunc func(ctx context.Context, claims IdentityClaimSet) error
	// OnError is a function that can be used to debug messages
	OnError func(err error)

	f publicKeySetFetcher
}

// NewAuthenticator returns a new http middleware based on the given parameters.
// If required parameters are nil, this function will panic.
func NewAuthenticator(a *Authenticator) func(http.Handler) http.Handler {
	if a.VerifyFunc == nil {
		panic("verify func must not be nil")
	}
	if a.Config == nil {
		panic("oauth2 config must not be nil")
	}
	c, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 100,
		MaxCost:     100,
		BufferItems: 100,
	})
	if err != nil {
		panic(err)
	}
	a.f = &fromCache{
		c: c,
		f: &fromURL{
			hc:         http.DefaultClient,
			url:        publicKeysURL,
			defaultTTL: 2 * time.Hour,
		},
	}
	if a.OnError == nil {
		a.OnError = func(err error) {}
	}
	return a.middleware
}

// IdentityClaimSet holds all the expected values for the various versions of the GCP
// identity token.
// More details:
// https://cloud.google.com/compute/docs/instances/verifying-instance-identity#payload
// https://developers.google.com/identity/sign-in/web/backend-auth#calling-the-tokeninfo-endpoint
type IdentityClaimSet struct {
	jws.ClaimSet

	// Email address of the default service account (only exists on GAE 2nd gen?)
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func (a *Authenticator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == a.OauthPath {
			a.callbackHandler(w, r)
			return
		}
		if a.SkipFunc != nil && a.SkipFunc(r) {
			next.ServeHTTP(w, r)
			return
		}
		ck, err := r.Cookie(a.CookieName)
		if err != nil || ck.Value == "" {
			a.redirect(w, r)
			return
		}
		token := ck.Value

		claims, err := a.verify(r.Context(), token)
		if err != nil {
			// c.cfg.Logger.Log("message", "id verify cookie failure, redirecting",
			// 	"error", err)
			a.redirect(w, r)
			return
		}
		_ = claims
		// add the user claims to the context and call the handlers below
		// r = r.WithContext(context.WithValue(r.Context(), claimsKey, claims))
		next.ServeHTTP(w, r)
	})
}

func (a *Authenticator) redirect(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		uri += "?" + r.URL.RawQuery
	}
	// avoid redirect loops
	if strings.HasPrefix(uri, a.OauthPath) {
		uri = "/"
	}
	redirectURL := a.Config.AuthCodeURL(uri, oauth2.AccessTypeOnline)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func (a *Authenticator) callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// verify state
	uri, ok := a.verifyState(ctx, r.FormValue("state"))
	if !ok {
		a.OnError(fmt.Errorf("invalid state"))
		forbidden(w)
		return
	}

	code := r.FormValue("code")
	if strings.TrimSpace(code) == "" {
		a.OnError(fmt.Errorf("missing code query param"))
		forbidden(w)
		return
	}

	token, err := a.Config.Exchange(ctx, code)
	if err != nil {
		a.OnError(fmt.Errorf("unable to exchange code: %w", err))
		forbidden(w)
		return
	}
	idI := token.Extra("id_token")
	if idI == nil {
		a.OnError(fmt.Errorf("missing id_token"))
		forbidden(w)
		return
	}
	id, ok := idI.(string)
	if !ok {
		a.OnError(fmt.Errorf("expected id_token to be a string but got %T", idI))
		forbidden(w)
		return
	}

	// they have authenticated, see if we can authorize them
	// via the given verifyFunc
	claims, err := a.verify(r.Context(), id)
	if err != nil {
		a.OnError(fmt.Errorf("verify error: %w", err))
		forbidden(w)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    a.CookieName,
		Secure:  a.SecureCookie,
		Value:   id,
		Domain:  a.CookieDomain,
		Expires: time.Unix(claims.Exp, 0),
	})
	http.Redirect(w, r, uri, http.StatusTemporaryRedirect)
}

func (a *Authenticator) verify(ctx context.Context, token string) (IdentityClaimSet, error) {
	var claims IdentityClaimSet
	hdr, rawPayload, err := decodeToken(token)
	if err != nil {
		return claims, fmt.Errorf("decode token error: %w", err)
	}

	keys, err := a.f.fetchPublicKeySet(ctx)
	if err != nil {
		return claims, fmt.Errorf("public key set error: %w", err)
	}

	key, err := keys.geKey(hdr.KeyID)
	if err != nil {
		return claims, fmt.Errorf("error getting key: %w", err)
	}

	err = jws.Verify(token, key)
	if err != nil {
		return claims, fmt.Errorf("error verifying jws: %w", err)
	}

	// use claims decoder func
	claims, err = decodeClaims(ctx, rawPayload)
	if err != nil {
		return claims, fmt.Errorf("error decoding claims: %w", err)
	}

	nowUnix := TimeNow().Unix()
	if nowUnix < claims.Iat {
		return claims, errors.New("invalid issue time")
	}
	if nowUnix > claims.Exp {
		return claims, fmt.Errorf("invalid expiration time")
	}
	err = a.VerifyFunc(ctx, claims)
	if err != nil {
		return IdentityClaimSet{}, fmt.Errorf("unverified: %w", err)
	}
	return claims, nil
}

func decodeClaims(ctx context.Context, bts []byte) (IdentityClaimSet, error) {
	var cs IdentityClaimSet
	err := json.Unmarshal(bts, &cs)
	if err != nil {
		return cs, err
	}
	return cs, nil
}

func (a *Authenticator) verifyState(ctx context.Context, state string) (string, bool) {
	if state == "" {
		return "", false
	}
	return state, true
}

// publicKeySet contains a set of keys acquired from a JWKS that has an expiration.
type publicKeySet struct {
	Expiry time.Time
	mu     sync.RWMutex
	Keys   map[string]*rsa.PublicKey
}

var reMaxAge = regexp.MustCompile("max-age=([0-9]*)")

type publicKeySetFetcher interface {
	fetchPublicKeySet(ctx context.Context) (*publicKeySet, error)
}

type fromURL struct {
	hc         *http.Client
	url        string
	defaultTTL time.Duration
}

func (f *fromURL) fetchPublicKeySet(ctx context.Context) (*publicKeySet, error) {
	r, err := http.NewRequest(http.MethodGet, f.url, nil)
	if err != nil {
		// return ks, errors.Wrap(err, "unable to create request")
		return nil, err
	}

	resp, err := f.hc.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ttl := f.defaultTTL
	if ccHeader := resp.Header.Get("cache-control"); ccHeader != "" {
		if match := reMaxAge.FindStringSubmatch(ccHeader); len(match) > 1 {
			maxAgeSeconds, err := strconv.ParseInt(match[1], 10, 64)
			if err != nil {
				// return ks, errors.Wrap(err, "unable to parse cache-control max age")
				return nil, err
			}
			ttl = time.Second * time.Duration(maxAgeSeconds)
		}
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		// return ks, errors.Wrap(err, "unable to read response")
		return nil, err
	}

	return publicKeySetFromJSON(payload, ttl)
}

type fromCache struct {
	c *ristretto.Cache
	f publicKeySetFetcher
}

func (f *fromCache) fetchPublicKeySet(ctx context.Context) (*publicKeySet, error) {
	const key = "public-key-set"
	resp, ok := f.c.Get(key)
	if !ok {
		pks, err := f.f.fetchPublicKeySet(ctx)
		if err != nil {
			return nil, err
		}
		f.c.SetWithTTL(key, pks, 1, time.Until(pks.Expiry))
		resp = pks
	}
	return resp.(*publicKeySet), nil
}

// jsonKeyResponse represents a JWK Set object.
type jsonKeyResponse struct {
	Keys []*jsonKey `json:"keys"`
}

// jsonKey represents a public or private key in JWK format.
type jsonKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// TimeNow is used internally to determine the current time. It has been abstracted to
// this global function as a mechanism to help with testing.
var TimeNow = func() time.Time { return time.Now() }

// publicKeySetFromJSON will accept a JSON payload in the format of the
// JSONKeyResponse and parse it into a PublicKeySet.
func publicKeySetFromJSON(payload []byte, ttl time.Duration) (*publicKeySet, error) {
	var (
		ks   publicKeySet
		keys jsonKeyResponse
	)
	err := json.Unmarshal(payload, &keys)
	if err != nil {
		return nil, err
	}

	ks = publicKeySet{
		Expiry: TimeNow().Add(ttl),
		Keys:   map[string]*rsa.PublicKey{},
	}

	for _, key := range keys.Keys {
		// we only plan on using RSA
		if key.Use == "sig" && key.Kty == "RSA" {
			n, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, err
			}
			e, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, err
			}
			ei := big.NewInt(0).SetBytes(e).Int64()
			ks.Keys[key.Kid] = &rsa.PublicKey{
				N: big.NewInt(0).SetBytes(n),
				E: int(ei),
			}
		}
	}
	return &ks, nil
}

func forbidden(w http.ResponseWriter) {
	// stop here here to prevent redirect chaos.
	code := http.StatusForbidden
	http.Error(w, http.StatusText(code), code)
}

func decodeToken(token string) (*jws.Header, []byte, error) {
	s := strings.Split(token, ".")
	if len(s) != 3 {
		return nil, nil, errors.New("invalid token")
	}

	dh, err := base64.RawURLEncoding.DecodeString(s[0])
	if err != nil {
		return nil, nil, err
	}
	var h jws.Header
	err = json.Unmarshal(dh, &h)
	if err != nil {
		return nil, nil, err
	}

	dcs, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return nil, nil, err
	}
	return &h, dcs, nil
}

// geKey will look for the given key ID in the key set and return it, if it exists.
func (ks *publicKeySet) geKey(id string) (*rsa.PublicKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if len(ks.Keys) == 0 {
		return nil, errors.New("no public keys found")
	}
	key, ok := ks.Keys[id]
	if !ok {
		// return nil, errors.Wrapf(ErrBadCreds, "key [%s] not found in set of size %d", id, len(ks.Keys))
		return nil, fmt.Errorf("key [%s] not found in set of size %d", id, len(ks.Keys))
	}
	return key, nil
}
