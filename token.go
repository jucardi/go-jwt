package jwt

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jucardi/go-jwt/signing"
)

// TokenData contains information about a JWT token
type TokenData struct {
	Raw       string            // Contains the original token string
	Algorithm signing.Algorithm // Indicates the signing algorithm used
	Header    TokenHeader       // The JWT header, first segment of the token
	Token     IToken            // The JWT claims, second segment of the token
	Signature []byte            // The JWT signature, third segment of the token

	signed    []byte
	validated bool
}

// ValidateSignature validates the signature of the parsed token with the provided public key and
// validates the claims of the token by invoking `IsValid`
//
//   {publicKey} - The public key to use for the signature validation
//
func (c *TokenData) ValidateAll(publicKey interface{}) error {
	if err := c.ValidateSignature(publicKey); err != nil {
		return err
	}
	return c.ValidateClaims()
}

// ValidateSignature validates the signature of the parsed token with the provided public key
//
//   {publicKey} - The public key to use for the signature validation
//
func (c *TokenData) ValidateSignature(publicKey interface{}) error {
	if c == nil {
		return newError(ErrNilToken, "failed to validate signature, token is nil")
	}
	if publicKey == nil {
		return newErrorf(ErrInvalidKey, "'publicKey' is required to validate the signature")
	}
	if c.validated {
		return nil
	}
	signer := c.Algorithm.Signer()
	if signer == nil {
		return newErrorf(ErrSigningAlgorithm, "algorithm '%s' not supported", c.Algorithm)
	}
	if err := signer.Verify(c.signed, c.Signature, publicKey); err != nil {
		return err
	}
	c.validated = true
	return nil
}

// ValidateClaims returns the result of `IsValid` implementation of the token
func (c *TokenData) ValidateClaims() error {
	if c == nil || c.Token == nil {
		return newErrorf(ErrNilToken, "failed to validate claims, token is nil")
	}
	return c.Token.IsValid()
}

// Sign attempts to obtain a signed JWT string token from the data contained within this instance.
//
//    {privateKey} - The private key to be used to sign the token
//
func (c *TokenData) Sign(privateKey interface{}) (string, error) {
	if c == nil || c.Token == nil {
		return "", newError(ErrNilToken, "failed to sign token, token is nil")
	}
	if privateKey == nil {
		return "", newError(ErrInvalidKey, "privateKey is required")
	}
	if c.Header == nil {
		c.Header = TokenHeader{}
	}
	if c.Header.Type() == "" {
		c.Header.SetType(jwtType)
	}
	if c.Algorithm != "" {
		c.Header.SetAlgorithm(c.Algorithm)
	}

	if c.Header.Algorithm() == "" {
		if alg := signing.DefaultFromKey(privateKey); alg == "" {
			return "", newErrorf(ErrSigningAlgorithm, "failed to determine default algorithm from provided privateKey")
		} else {
			c.Header.SetAlgorithm(alg)
		}
	}
	alg := c.Header.Algorithm()
	signer := alg.Signer()
	if signer == nil {
		return "", newErrorf(ErrSigningAlgorithm, "signer '%s' was not found", alg)
	}

	str, err := encode(c.Header, c.Token)
	if err != nil {
		return "", err
	}

	signature, err := signer.Sign(str, privateKey)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{str, signature}, "."), nil
}

// Sign marshals and signs the JWT token and returns the string representation of the token.
//
//   {token}      - The token implementation to sign
//   {privateKey} - The private key to use to sign the token
//   {algorithm}  - (optional) Indicates the signing algorithm to be used. If not provided,
//                  Sign will attempt to determine a valid default algorithm for the given
//                  public key type.
//
func Sign(token IToken, privateKey interface{}, algorithm ...signing.Algorithm) (string, error) {
	data := &TokenData{
		Token: token,
	}
	if len(algorithm) > 0 {
		data.Algorithm = algorithm[0]
	}
	return data.Sign(privateKey)
}

// Parse parses the provided JWT token. It does NOT validate the signature. For signature
// validation use the returned *TokenData.ValidateSignature
//
// If both parsing and validating the signature are required in one step, use
// `ParseAndValidate(token string, target IToken, publicKey interface{})` instead.
//
//   {tokenString} - The token string.
//   {target}      - The instance where the token claims will be deserialized to.
//
func Parse(tokenString string, target IToken) (*TokenData, error) {
	header, body, signature, signed, err := splitToken(tokenString)
	if err != nil {
		return nil, err
	}

	h := TokenHeader{}
	if err := json.Unmarshal(header, &h); err != nil {
		return nil, newErrorf(ErrUnmarshalFailed, "failed to unmarshal header, %s", err.Error())
	}
	if strings.ToLower(h.Type()) != "jwt" {
		return nil, fmt.Errorf("unknown token type '%s', only JWT tokens are supported", h.Type())
	}

	if err := json.Unmarshal(body, &target); err != nil {
		return nil, newErrorf(ErrUnmarshalFailed, "failed to unmarshal token body, '%s'", err)
	}

	ret := &TokenData{
		Raw:       tokenString,
		Algorithm: h.Algorithm(),
		Signature: signature,
		Token:     target,
		Header:    h,
		signed:    signed,
	}
	return ret, nil
}

// ParseAndValidate parses the provided JWT token, validates its signature and the integrity of the clains.
//
//   {tokenString} - The token string.
//   {target}      - The instance where the token claims will be deserialized to.
//   {publicKey} - The public key to use for the signature validation
//
func ParseAndValidate(tokenString string, target IToken, publicKey interface{}) (*TokenData, error) {
	if ret, err := Parse(tokenString, target); err != nil {
		return nil, err
	} else if err = ret.ValidateAll(publicKey); err != nil {
		return nil, err
	} else {
		return ret, nil
	}
}
