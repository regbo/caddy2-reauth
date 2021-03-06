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

package upstream

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"time"
	"log"
	"github.com/regbo/caddy2-reauth/backends"
	"github.com/regbo/caddy2-reauth/jsontypes"
)

// Interface guard
var _ backends.Driver = (*Upstream)(nil)

// BackendName name
const BackendName = "upstream"

const defaultTimeout = time.Minute

// Upstream backend provides authentication against an upstream http server.
// If the upstream request returns a http 200 status code then the user
// is considered logged in.
type Upstream struct {
	URL                *jsontypes.URL     `json:"url,omitempty"`
	Timeout            jsontypes.Duration `json:"timeout,omitempty"`
	InsecureSkipVerify bool               `json:"insecure_skip_verify,omitempty"`
	FollowRedirects    bool               `json:"follow_redirects,omitempty"`
	Match              *jsontypes.Regexp  `json:"match,omitempty"`
	Forward struct {
		RequestURI     bool     `json:"request_uri,omitempty"`
		Host     bool     `json:"host,omitempty"`
		Method  bool     `json:"method,omitempty"`
		IP      bool     `json:"ip,omitempty"`
		Headers []string `json:"headers,omitempty"`
	} `json:"forward"`
}

func noRedirectsPolicy(req *http.Request, via []*http.Request) error {
	return errors.New("follow redirects disabled")
}

// NewDriver returns a new instance of Upstream with some defaults
func NewDriver() *Upstream {
	return &Upstream{
		Timeout: jsontypes.Duration{Duration: defaultTimeout},
	}
}

// Validate verifies that this module is functional with the given configuration
func (h Upstream) Validate() error {
	if h.URL == nil {
		return errors.New("url to auth against is a required parameter")
	}

	if h.Timeout.Duration <= 0 {
		return errors.New("timeout must be greater than 0")
	}

	return nil
}

// Authenticate fulfils the backend interface
func (h Upstream) Authenticate(r *http.Request) (string, error) {
	c := &http.Client{
		Timeout: h.Timeout.Duration,
	}

	if !h.FollowRedirects {
		c.CheckRedirect = noRedirectsPolicy
	}

	if h.URL.Scheme == "https" && h.InsecureSkipVerify {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	
	data := url.Values{}
	h.copyRequest(r, data)
	
	resp, err := http.PostForm(h.URL.String(), data)

	if err != nil {
		log.Printf("url execute failed: %s", resp.StatusCode)
		return "", err
	}

	resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("status code failed: %s", resp.StatusCode)
		return "", nil
	}

	if h.Match != nil && h.Match.MatchString(resp.Request.URL.String()) {
		log.Printf("match check failed: %s", resp.Request.URL.String())
		return "", nil
	}
	return "unknown", nil
}

func (h Upstream) copyRequest(org *http.Request, data url.Values) {
	if h.isForwardHeadersWildcard() {
		copyRequestHeaders(org, data, "*")	
	}else{
		for _, header := range h.Forward.Headers {
			copyRequestHeaders(org, data, header)	
		}
	}
		
	if h.Forward.Host {
		data.Add("host", org.Host)
	}

	if h.Forward.RequestURI {
		data.Add("requestURI", org.RequestURI)
	}

	if h.Forward.Method {
		data.Add("method", org.Method)
	}

	if h.Forward.IP {
		data.Add("ip", org.RemoteAddr)
	}

}

func (h Upstream) isForwardHeadersWildcard() bool {
	for _, header := range h.Forward.Headers {
		if header == "*" {
			return true
		}
	}

	return false
}

func copyRequestHeaders(org *http.Request, data url.Values, nameFilter string) {
	if nameFilter == "*" {
		for name, values := range org.Header {
			for _, value := range values {
				data.Add("header-"+name, value)
			}
		}

	} else {
		for _, value := range org.Header.Values(nameFilter) {
					data.Add("header-"+nameFilter, value)
		}
	}

}
