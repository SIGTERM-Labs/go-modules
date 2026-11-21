package jwt

import (
	"net/http"
	"strings"
	"time"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/pkg/errors"
)

// jwksClient is shared across requests so its HTTP transport (and connection pool) is reused
// rather than rebuilt per request. jwkfetch.Client is safe for concurrent use.
var jwksClient = jwkfetch.NewClient()

// rawJWTFromAuthHeader returns a raw jwt token from the auth header
func rawJWTFromAuthHeader(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	auth = strings.TrimPrefix(auth, "bearer ")
	return strings.TrimPrefix(auth, "Bearer ")
}

// ParseTokenFromRequestWithJWKS Parses a jwt.Token from an Auth header, validating with JWKS Keys from an endpoint
func ParseTokenFromRequestWithJWKS(r *http.Request, jwksEndpoint string) (jwt.Token, error) {
	keyset, err := jwksClient.Fetch(r.Context(), jwksEndpoint)
	if err != nil {
		return nil, errors.Wrap(err, "ParseTokenFromHeaderWithJWKS():jwkfetch.Fetch()")
	}

	// Disable "infer algorithm" so this always uses the algorithm specified at the jwks endpoint or fails
	// (avoid something along the lines of https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
	// ParseString also validates essential claims (exp, nbf, iat) with the given skew
	token, err := jwt.ParseString(rawJWTFromAuthHeader(r),
		jwt.WithKeySet(keyset, jws.WithInferAlgorithmFromKey(false)),
		jwt.WithAcceptableSkew(60*time.Second),
	)
	if err != nil {
		return nil, errors.Wrap(err, "ParseTokenFromHeaderWithJWKS():jwt.ParseString()")
	}

	return token, nil
}
