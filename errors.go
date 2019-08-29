package jwt

import "fmt"

const (
	ErrNilToken         ErrorType = 0x1 << iota // Indicates the token is nil
	ErrInvalidKey                               // Indicates the provided key is invalid
	ErrSigningAlgorithm                         // Indicates the signing algorithm is not recognized
	ErrUnmarshalFailed                          // Indicates unmarshalling the token failed

	ErrTokenExpired  // Token is expired
	ErrBeforeIssued  // Issued date is in the future
	ErrNotBefore     // Not Before date is in the future
	ErrWrongIssuer   // Issuer validation failed
	ErrWrongAudience // Audience validation failed
)

func newError(t ErrorType, args ...interface{}) *Error {
	return &Error{Type: t, Message: fmt.Sprint(args...)}
}

func newErrorf(t ErrorType, format string, args ...interface{}) *Error {
	return &Error{Type: t, Message: fmt.Sprintf(format, args...)}
}

// ErrorType indicates the type of error
type ErrorType uint32

// IsType indicates whether the provided error matches the error type
func (t ErrorType) IsType(err error) bool {
	e, ok := err.(*Error)
	return ok && e != nil && e.Type&t == t
}

// Error error implementation which contains the error message and the error type
type Error struct {
	Type    ErrorType
	Message string // Message indicates the error message
}

// Error returns the error message
func (e *Error) Error() string {
	return e.Message
}

// String returns the error message
func (e *Error) String() string {
	return e.Message
}

// IsType indicates whether this error instance is of the provided type
func (e *Error) IsType(t ErrorType) bool {
	return e.Type&t == t
}
