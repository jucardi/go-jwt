package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jucardi/go-jwt/encoding"
)

func splitToken(token string) (header, body, signature, signed []byte, err error) {
	pieces := strings.Split(token, ".")

	if len(pieces) != 3 {
		err = errors.New("unexpected number of pieces")
		return
	}

	if header, err = encoding.DecodeSegment(pieces[0]); err != nil {
		err = fmt.Errorf("failed to decode header, %s", err.Error())
		return
	}
	if body, err = encoding.DecodeSegment(pieces[1]); err != nil {
		err = fmt.Errorf("failed to decode body, %s", err.Error())
		return
	}
	if signature, err = encoding.DecodeSegment(pieces[2]); err != nil {
		err = fmt.Errorf("failed to decode signature, %s", err.Error())
		return
	}

	signed = []byte(strings.Join(pieces[:len(pieces)-1], "."))
	return
}

func encode(header TokenHeader, token IToken) (string, error) {
	hBytes, err := json.Marshal(header)
	if err != nil {
		return "", errors.New("failed to marshal token header, " + err.Error())
	}
	tBytes, err := json.Marshal(token)
	if err != nil {
		return "", errors.New("failed to marshal token body, " + err.Error())
	}

	return strings.Join([]string{encoding.EncodeSegment(hBytes), encoding.EncodeSegment(tBytes)}, "."), nil
}

func getVal(m map[string]interface{}, key string) interface{} {
	if val, ok := m[key]; ok {
		return val
	}
	return nil
}

func getString(m map[string]interface{}, key string) string {
	if val, ok := getVal(m, key).(string); ok {
		return val
	}
	return ""
}

func getTimeInt(m map[string]interface{}, key string) int64 {
	val, ok := m[key]
	if !ok {
		return 0
	}
	switch v := val.(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	case json.Number:
		ret, _ := v.Int64()
		return ret
	case string:
		date, _ := time.Parse(time.RFC3339, v)
		return date.UTC().Unix()
	}
	return 0
}
