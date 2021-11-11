// Package pks defines Public Key Set functionality
package pks

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
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
)

// publicKeysURL is the known URL where google public keys
// are stored and rotated
const publicKeysURL = "https://www.googleapis.com/oauth2/v3/certs"

// PublicKeySetFetcher can return a public key set
// that is used to verify auth tokens.
type PublicKeySetFetcher interface {
	FetchPublicKeySet(ctx context.Context) (*PublicKeySet, error)
}

// New returns a new public key set fetcher
// with concurrent caching
func New() (PublicKeySetFetcher, error) {
	c, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 100,
		MaxCost:     100,
		BufferItems: 100,
	})
	if err != nil {
		panic(err)
	}
	return &fromCache{
		c: c,
		f: &fromURL{
			hc:         http.DefaultClient,
			url:        publicKeysURL,
			defaultTTL: 2 * time.Hour,
		},
	}, nil
}

// PublicKeySet contains a set of keys acquired from a JWKS that has an expiration.
type PublicKeySet struct {
	Expiry time.Time
	mu     sync.RWMutex
	keys   map[string]*rsa.PublicKey
}

// GeKey will look for the given key ID in the key set and return it, if it exists.
func (pks *PublicKeySet) GeKey(id string) (*rsa.PublicKey, error) {
	pks.mu.RLock()
	defer pks.mu.RUnlock()
	if len(pks.keys) == 0 {
		return nil, errors.New("no public keys found")
	}
	key, ok := pks.keys[id]
	if !ok {
		// return nil, errors.Wrapf(ErrBadCreds, "key [%s] not found in set of size %d", id, len(ks.Keys))
		return nil, fmt.Errorf("key [%s] not found in set of size %d", id, len(pks.keys))
	}
	return key, nil
}

var reMaxAge = regexp.MustCompile("max-age=([0-9]*)")

type fromURL struct {
	hc         *http.Client
	url        string
	defaultTTL time.Duration
}

func (f *fromURL) FetchPublicKeySet(ctx context.Context) (*PublicKeySet, error) {
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
	f PublicKeySetFetcher
}

func (f *fromCache) FetchPublicKeySet(ctx context.Context) (*PublicKeySet, error) {
	const key = "public-key-set"
	resp, ok := f.c.Get(key)
	if !ok {
		pks, err := f.f.FetchPublicKeySet(ctx)
		if err != nil {
			return nil, err
		}
		f.c.SetWithTTL(key, pks, 1, time.Until(pks.Expiry))
		resp = pks
	}
	return resp.(*PublicKeySet), nil
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

// publicKeySetFromJSON will accept a JSON payload in the format of the
// JSONKeyResponse and parse it into a PublicKeySet.
func publicKeySetFromJSON(payload []byte, ttl time.Duration) (*PublicKeySet, error) {
	var (
		ks   PublicKeySet
		keys jsonKeyResponse
	)
	err := json.Unmarshal(payload, &keys)
	if err != nil {
		return nil, err
	}

	ks = PublicKeySet{
		Expiry: time.Now().Add(ttl),
		keys:   map[string]*rsa.PublicKey{},
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
			ks.keys[key.Kid] = &rsa.PublicKey{
				N: big.NewInt(0).SetBytes(n),
				E: int(ei),
			}
		}
	}
	return &ks, nil
}
