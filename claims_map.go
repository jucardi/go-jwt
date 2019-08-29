package jwt

type MapClaims map[string]interface{}

func (m MapClaims) Audience() string {
	return getString(m, "aud")
}

func (m MapClaims) ExpiresAt() int64 {
	return getTimeInt(m, "exp")
}

func (m MapClaims) Id() string {
	return getString(m, "jti")
}

func (m MapClaims) IssuedAt() int64 {
	return getTimeInt(m, "iat")
}

func (m MapClaims) Issuer() string {
	return getString(m, "iss")
}

func (m MapClaims) NotBefore() int64 {
	return getTimeInt(m, "nbf")
}

func (m MapClaims) Subject() string {
	return getString(m, "sub")
}
