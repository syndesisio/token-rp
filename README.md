# Token Replacing Reverse Proxy

[![CircleCI branch](https://img.shields.io/circleci/project/github/redhat-ipaas/token-rp/master.svg)](https://circleci.com/gh/redhat-ipaas/token-rp)
[![license](https://img.shields.io/github/license/redhat-ipaas/token-rp.svg)](https://raw.githubusercontent.com/redhat-ipaas/token-rp/master/LICENSE)
[![Docker Automated buil](https://img.shields.io/docker/automated/redhat-ipaas/token-rp.svg)](https://hub.docker.com/r/rhipaas/token-rp/)

This repo contains a very simple reverse proxy that validates a JWT,
uses that JWT to retrieve a token for an identity provider from Keycloak
and sends requests to specified target using that retrieved token.

## Usage

```plain
Usage of token-rp:
  -ca-cert value
        Extra root certificate(s) that clients use when verifying server certificates
  -client-id string
        OpenID Connect client ID to verify
  -insecure-skip-verify
        If insecureSkipVerify is true, TLS accepts any certificate presented by the server and any host name in that certificate. In this mode, TLS is susceptible to man-in-the-middle attacks. This should be used only for testing.
  -issuer-url value
        URL to OpenID Connect discovery document
  -provider-alias string
        Keycloak provider alias to replace authorization token with
  -provider-type string
        Type of Keycloak IDP (currently supports openshift and github only)
  -proxy-url value
        URL to proxy requests to
  -tls-cert string
        Path to PEM-encoded certificate to use to serve over TLS
  -tls-key string
        Path to PEM-encoded key to use to serve over TLS
  -version
        Output version and exit
```

## Building

```bash
# Clone repo
$ git clone git://github.com/redhat-ipaas/token-rp.git
# Build binary
$ make build
# Run tests
$ make test
# Build image
$ make image
```