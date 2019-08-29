package jwt

import (
	"time"

	"github.com/jucardi/go-jwt/signing"
)

const (
	// TokenTypeAuth is the token type for an authentication token
	TokenTypeAuth TokenType = "auth"
	// TokenTypeAccess is the token type for an access token
	TokenTypeAccess TokenType = "access"
)

// TokenType indicates the type of token (auth, access)
type TokenType string

// ExtendedClaims defines the fields for authentication/access tokens
type ExtendedClaims struct {
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
	// NotBefore indicates when the token becomes valid in UNIX time (Not before)
	NotBefore int64 `json:"nbf,omitempty"`
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
}

// Valid ensures the token is valid. Validates that the token is not nil, not expired and is not used
// before its issued date and/or valid at date.
func (c *ExtendedClaims) IsValid() error {
	if c == nil {
		return newErrorf(ErrNilToken, "token is nil")
	}

	now := time.Now().UTC().Unix()

	if err := verifyExpiresAt(now, c.ExpiresAt); err != nil {
		return err
	}
	if err := verifyIssuedAt(now, c.IssuedAt); err != nil {
		return err
	}
	if err := verifyNotBefore(now, c.NotBefore); err != nil {
		return err
	}

	return nil
}

func (c *ExtendedClaims) Valid() error {
	return c.IsValid()
}

// Sign marshals and signs the JWT token and returns the string representation of the token.
//
//   {privateKey} - The private key to use to sign the token
//   {algorithm}  - (optional) Indicates the signing algorithm to be used. If not provided,
//                  Sign will attempt to determine a valid default algorithm for the given
//                  public key type.
//
func (c *ExtendedClaims) Sign(privateKey interface{}, algorithm ...signing.Algorithm) (string, error) {
	return Sign(c, privateKey, algorithm...)
}

// HasPermission indicates if the token has the provided permission(s). Permissions are indicated by bits.
//
//   {permission} - The permissions bits
//
func (c *ExtendedClaims) HasPermission(permission int) bool {
	return c != nil && c.Permissions&int32(permission) == int32(permission)
}
