/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Shannon Wynter
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package jwk

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ReneKroon/ttlcache/v2"
	"github.com/regbo/caddy2-reauth/backends"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Interface guard
var _ backends.Driver = (*Jwk)(nil)

// BackendName name
const BackendName = "jwk"
const BearerPrefix = "bearer "

// Jwk
type Jwk struct {
	TokenName               string        `json:"token_name,omitempty"`
	TokenSources            []string      `json:"token_sources,omitempty"`
	AuthorizedIssuersRegexP []string      `json:"authorized_issuers_regexp,omitempty"`
	JwkCacheDuration        int64         `json:"jwk_cache_duration,omitempty"`
	WellKnownPath           string        `json:"well_known_path,omitempty"`
	Debug                   bool          `json:"debug,omitempty"`
	ClaimFilters            []ClaimFilter `json:"claim_filter"`
	jwkCache                *ttlcache.Cache
	sync.Mutex
}

type ClaimFilter struct {
	Name   string   `json:"name,omitempty"`
	Values []string `json:"value,omitempty"`
}

// NewDriver returns a new instance of Jwk with some defaults
func NewDriver() *Jwk {
	return &Jwk{
		TokenName:               "access_token",
		TokenSources:            []string{"header", "cookie"},
		AuthorizedIssuersRegexP: []string{},
		JwkCacheDuration:        10 * 1000,
		WellKnownPath:           "/.well-known/jwks.json",
		ClaimFilters:            []ClaimFilter{},
	}
}

// Validate verifies that this module is functional with the given configuration
func (h Jwk) Validate() error {
	return nil
}

// Authenticate fulfils the backend interface
func (h *Jwk) Authenticate(r *http.Request) (string, error) {
	checkCookies := false
	checkHeader := false
	checkQuery := false
	for _, v := range h.TokenSources {
		if "cookie" == v {
			checkCookies = true
		}
		if "header" == v {
			checkHeader = true
		}
		if "query" == v {
			checkQuery = true
		}
	}
	var candidates []string
	if checkCookies {
		for _, c := range r.Cookies() {
			if c.Name == h.TokenName {
				candidates = append(candidates, c.Value)
			}
		}
	}
	if checkHeader {
		for _, v := range r.Header.Values("Authorization") {
			candidates = append(candidates, v)
		}
		for _, v := range r.Header.Values(h.TokenName) {
			candidates = append(candidates, v)
		}
	}
	if checkQuery {
		query := r.URL.Query()
		if query != nil {
			candidates = append(candidates, query.Get(h.TokenName))
		}
	}
	validated := false
	for _, v := range candidates {
		if h.validateCandidate(v) {
			validated = true
			break
		}
	}
	if !validated {
		return "", nil
	}
	return "unknown", nil
}

func (h *Jwk) validateCandidate(jwtStr string) bool {
	if strings.HasPrefix(strings.ToLower(jwtStr), BearerPrefix) {
		jwtStrRune := []rune(jwtStr)
		jwtStr = string(jwtStrRune[len(BearerPrefix):len(jwtStrRune)])
	}
	jwtStr = strings.TrimSpace(jwtStr)
	if jwtStr == "" {
		return false
	}

	parsedJwt, err := jwt.ParseSigned(jwtStr)
	if err != nil {
		h.debugLog(err)
		return false
	}
	issuerUrl, err := h.getIssuerUrl(parsedJwt)
	if err != nil {
		h.debugLog(err)
		return false
	}
	var jwkSet jose.JSONWebKeySet
	{ //lookup jwk set
		cached, err := h.getOrInitCache().Get(issuerUrl.String())
		if err != nil {
			h.debugLog(err)
			return false
		}
		jwkSet = cached.(jose.JSONWebKeySet)
	}
	{ //validate with  jwk set
		_, err := h.validate(jwtStr, parsedJwt, jwkSet)
		if err != nil {
			h.debugLog(err)
			return false
		}
	}
	return true
}

func (h *Jwk) getOrInitCache() *ttlcache.Cache {
	if h.jwkCache == nil {
		h.Lock()
		defer h.Unlock()
		if h.jwkCache == nil {
			cache := ttlcache.NewCache()
			if h.JwkCacheDuration < 0 {
				panic(errors.New("invalid jwk cache duration"))
			}
			cache.SkipTTLExtensionOnHit(true)
			_ = cache.SetTTL(time.Millisecond * time.Duration(h.JwkCacheDuration))
			cache.SetLoaderFunction(h.cacheLoad)
			h.jwkCache = cache
		}
	}
	return h.jwkCache
}

func (h *Jwk) cacheLoad(key string) (data interface{}, ttl time.Duration, err error) {
	issuerUrl, err := url.Parse(key)
	if err != nil {
		return nil, time.Nanosecond, err
	}
	jwkSet := h.getJwkSetFresh(issuerUrl)
	return jwkSet, ttl, nil
}

func (h *Jwk) validate(jwtStr string, jwt *jwt.JSONWebToken, jwkSet jose.JSONWebKeySet) (*jose.JSONWebSignature, error) {
	jwtSig, err := jose.ParseSigned(jwtStr)
	if err != nil {
		return nil, err
	}
	for _, key := range jwkSet.Keys {
		kidMatch := false
		kidFound := false
		for _, sig := range jwtSig.Signatures {
			kid := sig.Header.KeyID
			if kid == "" {
				continue
			}
			kidFound = true
			if kid == key.KeyID {
				kidMatch = true
				break
			}
		}
		if kidFound && !kidMatch {
			continue
		}
		_, err := jwtSig.Verify(key)
		if err != nil {
			h.debugLogF("failed to verify jwt: %s", err)
			continue
		}
		err = h.validateClaims(jwt, key)
		if err != nil {
			h.debugLogF("failed to verify claims: %s", err)
			continue
		}
		return jwtSig, nil
	}
	return nil, errors.New("failed to validate jwt")
}
func (h *Jwk) validateClaims(jwt *jwt.JSONWebToken, key jose.JSONWebKey) error {
	if h.ClaimFilters == nil || len(h.ClaimFilters) == 0 {
		h.debugLog("claim filters skipped")
		return nil
	}
	claimData := make(map[string]interface{})
	err := jwt.Claims(key, &claimData)
	if err != nil {
		return err
	}
	for _, claim := range h.ClaimFilters {
		claimObj := claimData[claim.Name]
		var claimValues []string
		switch x := claimObj.(type) {
		case string:
			claimValues = append(claimValues, x)
		case []interface{}:
			for _, v := range x {
				claimValues = append(claimValues, fmt.Sprintf("%s", v))
			}
		default:
			//unable to parse
		}
		if claimValues == nil {
			continue
		}
		for _, filterValue := range claim.Values {
			for _, claimValue := range claimValues {
				if filterValue == claimValue {
					h.debugLogF("claims match. name:%s value:%s found:%s", claim.Name, filterValue, claimValue)
					return nil
				}
			}
		}

	}
	return errors.New("claim validation failed")
}

func (h *Jwk) getJwkSetFresh(issuerUrl *url.URL) jose.JSONWebKeySet {
	jwkSet := jose.JSONWebKeySet{}
	for i := 0; i < 2; i++ {
		var attemptUrl *url.URL
		if i == 0 {
			attemptUrl = issuerUrl
		} else {
			urlWellKnown, err := h.getIssuerUrlWellKnown(issuerUrl)
			if err != nil {
				h.debugLog(err)
				continue
			}
			attemptUrl = urlWellKnown
		}
		err := addToJwkSet(&jwkSet, attemptUrl)
		if err != nil {
			h.debugLog(err)
		}
	}
	return jwkSet
}

func (h *Jwk) getIssuerUrl(jwt *jwt.JSONWebToken) (*url.URL, error) {
	out := make(map[string]interface{})
	if err := jwt.UnsafeClaimsWithoutVerification(&out); err != nil {
		return nil, err
	}
	issuer := fmt.Sprintf("%v", out["iss"])
	issuerUrl, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	validIssuer := false
	if h.AuthorizedIssuersRegexP != nil {
		urlStr := issuerUrl.String()
		for _, filter := range h.AuthorizedIssuersRegexP {
			if filter == "*" {
				validIssuer = true
			} else {
				matched, _ := regexp.MatchString(filter, urlStr)
				if matched {
					validIssuer = true
				}
			}
			if validIssuer {
				break
			}
		}
	}
	if !validIssuer {
		return nil, errors.New(fmt.Sprintf("issuer url is not authroized:%s", issuerUrl))
	}
	return issuerUrl, nil
}

func (h *Jwk) getIssuerUrlWellKnown(issuerUrl *url.URL) (*url.URL, error) {
	if issuerUrl == nil {
		return nil, errors.New("issuer url required")
	}

	if strings.HasSuffix(issuerUrl.Path, h.WellKnownPath) {
		return nil, errors.New(fmt.Sprintf("issuer is well known. url:%s", issuerUrl))
	}
	issuerUrlWellKnown, _ := url.Parse(issuerUrl.String())
	if strings.HasSuffix(issuerUrlWellKnown.Path, "/") {
		pathRune := []rune(issuerUrlWellKnown.Path)
		issuerUrlWellKnown.Path = string(pathRune[0 : len(pathRune)-1])
	}
	issuerUrlWellKnown.Path = issuerUrlWellKnown.Path + h.WellKnownPath
	return issuerUrlWellKnown, nil
}

func (h Jwk) debugLog(v interface{}) {
	h.debugLogF("%s", v)
}

func (h Jwk) debugLogF(format string, v ...interface{}) {
	if !h.Debug {
		return
	}
	log.Printf(format, v)
}

func addToJwkSet(jwkSet *jose.JSONWebKeySet, url *url.URL) error {
	if url == nil {
		return errors.New("url is required")
	}
	resp, err := http.Get(url.String())
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return errors.New(fmt.Sprintf("jwks lookup failed. url:%s err:%s", url, err))
	}
	body, _ := ioutil.ReadAll(resp.Body)
	if resp != nil {
		_ = resp.Body.Close()
	}
	jwkSetAppend := jose.JSONWebKeySet{}
	if err := json.Unmarshal(body, &jwkSetAppend); err != nil {
		return errors.New(fmt.Sprintf("jwks parse failed. url:%s err:%s", url, err))
	}
	for _, v := range jwkSetAppend.Keys {
		jwkSet.Keys = append(jwkSet.Keys, v)
	}
	return nil
}
