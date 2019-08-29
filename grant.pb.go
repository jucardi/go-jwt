// Code generated by protoc-gen-go. DO NOT EDIT.
// source: grant.proto

package jwt

import (
	fmt "fmt"
	math "math"

	proto "github.com/golang/protobuf/proto"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Grant encapsulates a generated token and indicates the token type and expiration without having to parse it
//
// swagger: model Grant
type Grant struct {
	// Token is the token string.
	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	// Exp is the iso8601 time timestamp when the token will expire
	Exp string `protobuf:"bytes,2,opt,name=exp,proto3" json:"exp,omitempty"`
	// Purpose indicates the token purpose
	Type                 string   `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-" yaml:"-" gorm:"-" bson:"-"`
	XXX_unrecognized     []byte   `json:"-" yaml:"-" gorm:"-" bson:"-"`
	XXX_sizecache        int32    `json:"-" yaml:"-" gorm:"-" bson:"-"`
}

func (m *Grant) Reset()         { *m = Grant{} }
func (m *Grant) String() string { return proto.CompactTextString(m) }
func (*Grant) ProtoMessage()    {}
func (*Grant) Descriptor() ([]byte, []int) {
	return fileDescriptor_d8d80872b3060482, []int{0}
}

func (m *Grant) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Grant.Unmarshal(m, b)
}
func (m *Grant) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Grant.Marshal(b, m, deterministic)
}
func (m *Grant) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Grant.Merge(m, src)
}
func (m *Grant) XXX_Size() int {
	return xxx_messageInfo_Grant.Size(m)
}
func (m *Grant) XXX_DiscardUnknown() {
	xxx_messageInfo_Grant.DiscardUnknown(m)
}

var xxx_messageInfo_Grant proto.InternalMessageInfo

func (m *Grant) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *Grant) GetExp() string {
	if m != nil {
		return m.Exp
	}
	return ""
}

func (m *Grant) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func init() {
	proto.RegisterType((*Grant)(nil), "jwt.Grant")
}

func init() { proto.RegisterFile("grant.proto", fileDescriptor_d8d80872b3060482) }

var fileDescriptor_d8d80872b3060482 = []byte{
	// 98 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4e, 0x2f, 0x4a, 0xcc,
	0x2b, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0xce, 0x2a, 0x2f, 0x51, 0x72, 0xe6, 0x62,
	0x75, 0x07, 0x89, 0x09, 0x89, 0x70, 0xb1, 0x96, 0xe4, 0x67, 0xa7, 0xe6, 0x49, 0x30, 0x2a, 0x30,
	0x6a, 0x70, 0x06, 0x41, 0x38, 0x42, 0x02, 0x5c, 0xcc, 0xa9, 0x15, 0x05, 0x12, 0x4c, 0x60, 0x31,
	0x10, 0x53, 0x48, 0x88, 0x8b, 0xa5, 0xa4, 0xb2, 0x20, 0x55, 0x82, 0x19, 0x2c, 0x04, 0x66, 0x27,
	0xb1, 0x81, 0x0d, 0x34, 0x06, 0x04, 0x00, 0x00, 0xff, 0xff, 0xc6, 0x01, 0x70, 0xae, 0x5f, 0x00,
	0x00, 0x00,
}