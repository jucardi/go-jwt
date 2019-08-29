package jwt

type StandardClaims struct {
	Aud string `json:"aud,omitempty"`
	Exp int64  `json:"exp,omitempty"`
	Jti string `json:"jti,omitempty"`
	Iat int64  `json:"iat,omitempty"`
	Iss string `json:"iss,omitempty"`
	Nbf int64  `json:"nbf,omitempty"`
	Sub string `json:"sub,omitempty"`
}

func (s *StandardClaims) Audience() string {
	return s.Aud
}

func (s *StandardClaims) ExpiresAt() int64 {
	return s.Exp
}

func (s *StandardClaims) Id() string {
	return s.Jti
}

func (s *StandardClaims) IssuedAt() int64 {
	return s.Iat
}

func (s *StandardClaims) Issuer() string {
	return s.Iss
}

func (s *StandardClaims) NotBefore() int64 {
	return s.Nbf
}

func (s *StandardClaims) Subject() string {
	return s.Subject()
}
