package jwt

import "time"

func verifyExpiresAt(now, exp int64) error {
	if exp != 0 && exp < now {
		return newErrorf(ErrTokenExpired, "token expired %s ago", time.Duration(now-exp))
	}
	return nil
}

func verifyIssuedAt(now, iat int64) error {
	if iat != 0 && iat > now {
		return newErrorf(ErrBeforeIssued, "token used %s before issued", time.Duration(iat-now))
	}
	return nil
}

func verifyNotBefore(now, nbf int64) error {
	if nbf != 0 && nbf > now {
		return newErrorf(ErrNotBefore, "token not valid for the next %s", time.Duration(now-nbf))
	}
	return nil
}

func verifyIssuer(expected, iss string) error {
	if expected != "" && expected != iss {
		return newErrorf(ErrWrongIssuer, "wrong issuer %s", iss)
	}
	return nil
}

func verifyAudience(expected, aud string) error {
	if expected != "" && expected != aud {
		return newErrorf(ErrWrongAudience, "wrong audience %s", aud)
	}
	return nil
}
