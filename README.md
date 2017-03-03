# Token Replacing Reverse Proxy

This repo contains a very simple reverse proxy that validates a JWT,
uses that JWT to retrieve a token for an identity provider from Keycloak
and sends requests to specified target using that retrieved token.

## Usage

```plain
Usage of token-rp:
  -client-id string
        OpenID Connect client ID to verify
  -issuer-url value
        URL to OpenID Connect discovery document
  -provider-alias string
        Keycloak provider alias to replace authorization token with
  -provider-type string
        Type of Keycloak IDP (currently supports openshift and github only)
  -proxy-url value
        URL to proxy requests to
```

## Building

```bash
$ go get -u -v github.com/redhat-ipaas/token-rp

github.com/redhat-ipaas/token-rp (download)
```