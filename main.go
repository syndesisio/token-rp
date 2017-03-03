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
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/vulcand/oxy/forward"

	"crypto/x509"

	"github.com/redhat-ipaas/token-rp/pkg/version"
)

var (
	issuerURLFlag      urlFlag
	proxyURLFlag       urlFlag
	clientID           string
	idpAlias           string
	idpType            string
	serverCertFile     string
	serverKeyFile      string
	insecureSkipVerify bool
	versionFlag        bool
	caCerts            stringSliceFlag

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
	flagSet.StringVar(&serverCertFile, "tls-cert", "", "Path to PEM-encoded certificate to use to serve over TLS")
	flagSet.StringVar(&serverKeyFile, "tls-key", "", "Path to PEM-encoded key to use to serve over TLS")
	flagSet.BoolVar(&versionFlag, "version", false, "Output version and exit")
	flagSet.BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "If insecureSkipVerify is true, TLS accepts any certificate presented by the server and any host name in that certificate. In this mode, TLS is susceptible to man-in-the-middle attacks. This should be used only for testing.")
	flagSet.Var(&caCerts, "ca-cert", "Extra root certificate(s) that clients use when verifying server certificates")
}

func main() {
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if versionFlag {
		fmt.Printf("%s %s (%s)\n", filepath.Base(os.Args[0]), version.AppVersion, version.BuildDate)
		os.Exit(0)
	}

	if idpType != openshiftIDPType && idpType != githubIDPType {
		fmt.Fprintf(os.Stderr, "Unknown provider-type: %s\n", idpType)
		os.Exit(2)
	}
	proxyTargetTokenType := "Bearer"
	if idpType == githubIDPType {
		proxyTargetTokenType = "token"
	}

	if len(serverCertFile) > 0 && len(serverKeyFile) == 0 {
		fmt.Fprint(os.Stderr, "tls-cert specified with no tls-key\n")
		os.Exit(2)
	}
	if len(serverCertFile) == 0 && len(serverKeyFile) > 0 {
		fmt.Fprint(os.Stderr, "tls-key specified with no tls-cert\n")
		os.Exit(2)
	}

	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create cert pool: %v\n", err)
		os.Exit(2)
	}

	for _, cert := range caCerts {
		certBytes, err := ioutil.ReadFile(cert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read CA certificate %s: %v\n", cert, err)
			os.Exit(2)
		}
		caCertPool.AppendCertsFromPEM(certBytes)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
			RootCAs:            caCertPool,
		},
	}
	hc := &http.Client{
		Transport: tr,
	}

	issuerURL := strings.TrimSuffix(strings.TrimSuffix(issuerURLFlag.String(), discoveryPath), "/")
	providerConfig, err := oidc.FetchProviderConfig(hc, issuerURL)
	if err != nil {
		log.Fatal(err)
	}

	oidcClient, err := oidc.NewClient(oidc.ClientConfig{
		HTTPClient:     hc,
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

	fwd, err := forward.New(forward.RoundTripper(tr))
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

		targetToken, err := retrieveTargetToken(issuerURL, idpAlias, idpType, token, hc)
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
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	if len(serverCertFile) > 0 {
		err = s.ListenAndServeTLS(serverCertFile, serverKeyFile)
	} else {
		err = s.ListenAndServe()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Server failed: %v", err)
	}
}

type jsonBrokerToken struct {
	AccessToken string `json:"access_token"`
}

func retrieveTargetToken(issuerURL, idpAlias, idpType, token string, hc *http.Client) (string, error) {
	tokenURL := issuerURL + "/broker/" + idpAlias + "/token"
	tokenReq, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		return "", err
	}
	tokenReq.Header.Set("Authorization", "Bearer "+token)
	tokenResp, err := hc.Do(tokenReq)
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
