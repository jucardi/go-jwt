package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jucardi/go-jwt/signing"
)

const (
	// TokenTypeAuth is the token type for an authentication token
	TokenTypeAuth TokenType = "auth"
	// TokenTypeAccess is the token type for an access token
	TokenTypeAccess TokenType = "access"

	headerAlgKey  = "alg"
	headerTypeKey = "typ"
)

// ParseToken parses the provided JWT token. It does not validate the signature until
// `token.ValidateSignature(publicKey interface{})` is called.
//
// If both parsing and validating the signature are required in one step, use
// `ValidateToken(token string, publicKey interface{})` instead.
//
//   {token} - The token string
//
func ParseToken(token string) (*Token, error) {
	header, body, signature, signed, err := splitToken(token)
	if err != nil {
		return nil, err
	}

	h := TokenHeader{}
	if err := json.Unmarshal(header, &h); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header, %s", err.Error())
	}
	if strings.ToLower(h.Type()) != "jwt" {
		return nil, fmt.Errorf("unknown token type '%s', only JWT tokens are supported", h.Type())
	}

	ret := &Token{
		internal: &tokenMetadata{
			alg:       h.Algorithm(),
			signed:    signed,
			signature: signature,
		},
	}

	if err := json.Unmarshal(body, &ret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token body, '%s'", err)
	}

	return ret, nil
}

// ValidateToken parses the given token and validates its signature. Errors if either the parsing,
// the signature validation fail or token.Valid() failed
//
//   {token}      - The token string
//   {publicKey}  - The public key to use for the signature validation
//
func ValidateToken(token string, publicKey interface{}) (*Token, error) {
	if token, err := ParseToken(token); err != nil {
		return nil, err
	} else if err = token.ValidateSignature(publicKey); err != nil {
		return nil, err
	} else if err = token.Valid(); err != nil {
		return nil, err
	} else {
		return token, nil
	}
}

// TokenType indicates the type of token (auth, access)
type TokenType string

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

// Token defines the fields for authentication/access tokens
type Token struct {
	// Audience indicates the audience of this token
	Audience string `json:"aud,omitempty"`
	// ExpiresAt indicates the expiration of the token in UNIX time
	ExpiresAt int64 `json:"exp,omitempty"`
	// Id is an optional unique id for the token
	Id string `json:"jti,omitempty"`
	// IssuedAt at indicates when the token was issued in UNIX time
	IssuedAt int64 `json:"iat,omitempty"`
	// Issuer indicates who issued the token
	Issuer string `json:"iss,omitempty"`
	// ValidAt indicates when the token becomes valid in UNIX time (Not before)
	ValidAt int64 `json:"nbf,omitempty"`
	// Subject indicates the subject of the token
	Subject string `json:"sub,omitempty"`
	// Type indicates the token purpose (Authenticate, Access) based on the JWT standards
	Type TokenType `json:"type,omitempty"`
	// Scope indicates the scope of the token
	Scope string `json:"scope,omitempty"`
	// Permissions indicates the allowed permissions for this token. Permissions should be defined with binary bits so they are joined together with a bitwise OR operation
	Permissions int32 `json:"permissions,omitempty"`
	// Fields contains any additional fields to be included in the token
	Fields map[string]interface{} `json:"fields,omitempty"`

	internal *tokenMetadata
}

// ValidateSignature validates the signature of the parsed token with the provided public key
//
//   {publicKey} - The public key to use for the signature validation
//
func (c *Token) ValidateSignature(publicKey interface{}) error {
	if c == nil {
		return errors.New("token is nil")
	}
	if c.internal == nil {
		return errors.New("token has no header metadata, this token was not parsed from a string, unable to validate signature")
	}
	if publicKey == nil {
		return errors.New("'publicKey' is required to validate the signature")
	}
	// Case for previously validated with the provided key to avoid computing the same validation twice.
	if c.internal.validated && c.internal.publicKey == publicKey {
		return nil
	}
	signer := c.internal.alg.Signer()
	if signer == nil {
		return fmt.Errorf("algorithm '%s' not supported", c.internal.alg)
	}
	if err := signer.Verify(c.internal.signed, c.internal.signature, publicKey); err != nil {
		return err
	}
	c.internal.validated = true
	c.internal.publicKey = publicKey
	return nil
}

// Sign marshals and signs the JWT token and returns the string representation of the token.
//
//   {privateKey} - The private key to use to sign the token
//   {algorithm}  - (optional) Indicates the signing algorithm to be used. If not provided,
//                  Sign will attempt to determine a valid default algorithm for the given
//                  public key type.
//
func (c *Token) Sign(privateKey interface{}, algorithm ...signing.Algorithm) (string, error) {
	if c == nil {
		return "", errors.New("token is nil")
	}
	if privateKey == nil {
		return "", errors.New("'privateKey' is required")
	}
	var alg signing.Algorithm
	if len(algorithm) > 0 {
		alg = algorithm[0]
	} else if a := signing.DefaultFromKey(privateKey); a == "" {
		return "", errors.New("failed to determine default algorithm from provided privateKey")
	} else {
		alg = a
	}

	signer := alg.Signer()
	if signer == nil {
		return "", fmt.Errorf("signer '%s' was not found", alg)
	}

	str, err := encode(alg, c)
	if err != nil {
		return "", err
	}

	signature, err := signer.Sign(str, privateKey)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{str, signature}, "."), nil
}

// Valid ensures the token is valid. Validates that the token is not nil, not expired and is not used
// before its issued date and/or valid at date.
func (c *Token) Valid() error {
	if c == nil {
		return errors.New("token is nil")
	}

	now := time.Now().UTC().Unix()

	if c.ExpiresAt != 0 && c.ExpiresAt < now {
		return errors.New("token has expired")
	}

	if c.IssuedAt != 0 && c.IssuedAt > now {
		return errors.New("token used before issued time")
	}

	if c.ValidAt != 0 && c.ValidAt > now {
		return errors.New("token is not valid yet")
	}

	return nil
}

// HasPermission indicates if the token has the provided permission(s). Permissions are indicated by bits.
//
//   {permission} - The permissions bits
//
func (c *Token) HasPermission(permission int) bool {
	return c != nil && c.Permissions&int32(permission) == int32(permission)
}

type tokenMetadata struct {
	signed    []byte
	signature []byte
	validated bool
	alg       signing.Algorithm
	publicKey interface{}
}
