//    Copyright 2017 Red Hat, Inc.
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/vulcand/oxy/forward"
)

var (
	issuerURLFlag urlFlag
	proxyURLFlag  urlFlag
	clientID      string
	idpAlias      string
	idpType       string

	flagSet = flag.NewFlagSet("token-rp", flag.ContinueOnError)
)

const (
	discoveryPath = "/.well-known/openid-configuration"

	githubIDPType    = "github"
	openshiftIDPType = "openshift"
)

func init() {
	flagSet.Var(&issuerURLFlag, "issuer-url", "URL to OpenID Connect discovery document")
	flagSet.Var(&proxyURLFlag, "proxy-url", "URL to proxy requests to")
	flagSet.StringVar(&clientID, "client-id", "", "OpenID Connect client ID to verify")
	flagSet.StringVar(&idpAlias, "provider-alias", "", "Keycloak provider alias to replace authorization token with")
	flagSet.StringVar(&idpType, "provider-type", "", "Type of Keycloak IDP (currently supports openshift and github only)")
}

func main() {
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if idpType != openshiftIDPType && idpType != githubIDPType {
		fmt.Fprintf(os.Stderr, "Unknown provider-type: %s", idpType)
		os.Exit(2)
	}
	proxyTargetTokenType := "Bearer"
	if idpType == githubIDPType {
		proxyTargetTokenType = "token"
	}

	issuerURL := strings.TrimSuffix(strings.TrimSuffix(issuerURLFlag.String(), discoveryPath), "/")

	providerConfig, err := oidc.FetchProviderConfig(nil, issuerURL)
	if err != nil {
		log.Fatal(err)
	}

	oidcClient, err := oidc.NewClient(oidc.ClientConfig{
		ProviderConfig: providerConfig,
		Credentials: oidc.ClientCredentials{
			ID: clientID,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	syncStop := oidcClient.SyncProviderConfig(issuerURL)
	defer close(syncStop)

	fwd, err := forward.New()
	if err != nil {
		log.Fatal(err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token, err := jwtmiddleware.FromAuthHeader(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if len(token) == 0 {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		jwt, err := jose.ParseJWT(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		err = oidcClient.VerifyJWT(jwt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		targetToken, err := retrieveTargetToken(issuerURL, idpAlias, idpType, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		req.Header.Set("Authorization", proxyTargetTokenType+" "+targetToken)

		proxyURL := (url.URL)(proxyURLFlag)
		req.URL = &proxyURL
		fwd.ServeHTTP(w, req)
	})

	s := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}
	s.ListenAndServe()
}

type jsonBrokerToken struct {
	AccessToken string `json:"access_token"`
}

func retrieveTargetToken(issuerURL, idpAlias, idpType, token string) (string, error) {
	tokenURL := issuerURL + "/broker/" + idpAlias + "/token"
	tokenReq, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		return "", err
	}
	tokenReq.Header.Set("Authorization", "Bearer "+token)
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		return "", err
	}
	defer func() { _ = tokenResp.Body.Close() }()

	if tokenResp.StatusCode != 200 {
		return "", fmt.Errorf("unable to retrieve broker token: %s", tokenResp.Status)
	}

	b, err := ioutil.ReadAll(tokenResp.Body)
	if err != nil {
		return "", err
	}

	if idpType == openshiftIDPType {
		var brokerToken jsonBrokerToken
		if err = json.Unmarshal(b, &brokerToken); err != nil {
			return "", err
		}
		if len(brokerToken.AccessToken) > 0 {
			return brokerToken.AccessToken, nil
		}

		return "", fmt.Errorf("missing access token in broker token")
	}

	if idpType == githubIDPType {
		query, err := url.ParseQuery(string(b))
		if err != nil {
			return "", err
		}

		accessToken := query.Get("access_token")
		if len(accessToken) > 0 {
			return accessToken, nil
		}

		return "", fmt.Errorf("missing access token in broker token")
	}

	return "", fmt.Errorf("broker token in unknown format")
}
