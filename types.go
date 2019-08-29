package jwt

import "github.com/jucardi/go-jwt/signing"

const (
	headerAlgKey  = "alg"
	headerTypeKey = "typ"

	jwtType = "JWT"
)

type IToken interface {
	IsValid() error
}

type IStandardClaims interface {
	// Audience indicates the audience of this token
	Audience() string
	// ExpiresAt indicates the expiration of the token in UNIX time
	ExpiresAt() int64
	// Id is an optional unique id for the token
	Id() string
	// IssuedAt at indicates when the token was issued in UNIX time
	IssuedAt() int64
	// Issuer indicates who issued the token
	Issuer() string
	// NotBefore indicates when the token becomes valid in UNIX time
	NotBefore() int64
	// Subject indicates the subject of the token
	Subject() string
}

// TokenHeader represents the header of the token
type TokenHeader map[string]interface{}

// Algorithm retrieves the signing algorithm specified in the header
func (h TokenHeader) Algorithm() signing.Algorithm {
	return signing.Algorithm(getString(h, headerAlgKey))
}

// Type indicates the token type (JWT)
func (h TokenHeader) Type() string {
	return getString(h, headerTypeKey)
}

// SetAlgorithm sets the algorithm to be used in the token
func (h TokenHeader) SetAlgorithm(alg signing.Algorithm) {
	h[headerAlgKey] = alg.String()
}

// SetType sets the token type value
func (h TokenHeader) SetType(t string) {
	h[headerTypeKey] = t
}
