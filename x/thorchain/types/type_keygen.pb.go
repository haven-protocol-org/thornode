// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: thorchain/v1/x/thorchain/types/type_keygen.proto

package types

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	gitlab_com_thorchain_thornode_common "gitlab.com/thorchain/thornode/common"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type KeygenType int32

const (
	KeygenType_UnknownKeygen   KeygenType = 0
	KeygenType_AsgardKeygen    KeygenType = 1
	KeygenType_YggdrasilKeygen KeygenType = 2
)

var KeygenType_name = map[int32]string{
	0: "UnknownKeygen",
	1: "AsgardKeygen",
	2: "YggdrasilKeygen",
}

var KeygenType_value = map[string]int32{
	"UnknownKeygen":   0,
	"AsgardKeygen":    1,
	"YggdrasilKeygen": 2,
}

func (x KeygenType) String() string {
	return proto.EnumName(KeygenType_name, int32(x))
}

func (KeygenType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_633864b709de4dd1, []int{0}
}

type Keygen struct {
	ID      gitlab_com_thorchain_thornode_common.TxID `protobuf:"bytes,1,opt,name=id,proto3,casttype=gitlab.com/thorchain/thornode/common.TxID" json:"id,omitempty"`
	Type    KeygenType                                `protobuf:"varint,2,opt,name=type,proto3,enum=types.KeygenType" json:"type,omitempty"`
	Members []string                                  `protobuf:"bytes,3,rep,name=members,proto3" json:"members,omitempty"`
}

func (m *Keygen) Reset()      { *m = Keygen{} }
func (*Keygen) ProtoMessage() {}
func (*Keygen) Descriptor() ([]byte, []int) {
	return fileDescriptor_633864b709de4dd1, []int{0}
}
func (m *Keygen) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Keygen) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Keygen.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Keygen) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Keygen.Merge(m, src)
}
func (m *Keygen) XXX_Size() int {
	return m.Size()
}
func (m *Keygen) XXX_DiscardUnknown() {
	xxx_messageInfo_Keygen.DiscardUnknown(m)
}

var xxx_messageInfo_Keygen proto.InternalMessageInfo

type KeygenBlock struct {
	Height  int64    `protobuf:"varint,1,opt,name=height,proto3" json:"height,omitempty"`
	Keygens []Keygen `protobuf:"bytes,4,rep,name=keygens,proto3" json:"keygens"`
}

func (m *KeygenBlock) Reset()      { *m = KeygenBlock{} }
func (*KeygenBlock) ProtoMessage() {}
func (*KeygenBlock) Descriptor() ([]byte, []int) {
	return fileDescriptor_633864b709de4dd1, []int{1}
}
func (m *KeygenBlock) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *KeygenBlock) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_KeygenBlock.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *KeygenBlock) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeygenBlock.Merge(m, src)
}
func (m *KeygenBlock) XXX_Size() int {
	return m.Size()
}
func (m *KeygenBlock) XXX_DiscardUnknown() {
	xxx_messageInfo_KeygenBlock.DiscardUnknown(m)
}

var xxx_messageInfo_KeygenBlock proto.InternalMessageInfo

func init() {
	proto.RegisterEnum("types.KeygenType", KeygenType_name, KeygenType_value)
	proto.RegisterType((*Keygen)(nil), "types.Keygen")
	proto.RegisterType((*KeygenBlock)(nil), "types.KeygenBlock")
}

func init() {
	proto.RegisterFile("thorchain/v1/x/thorchain/types/type_keygen.proto", fileDescriptor_633864b709de4dd1)
}

var fileDescriptor_633864b709de4dd1 = []byte{
	// 347 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x91, 0x4f, 0x4f, 0xf2, 0x30,
	0x1c, 0xc7, 0xdb, 0x8d, 0x07, 0x42, 0x79, 0x50, 0xa8, 0xc6, 0x2c, 0x1e, 0xca, 0x42, 0x62, 0x32,
	0x4d, 0xdc, 0x14, 0x5e, 0x81, 0x93, 0x98, 0x10, 0x6f, 0x0b, 0x1c, 0xf4, 0x62, 0xc6, 0xd6, 0x74,
	0x0b, 0xac, 0x25, 0xdb, 0xa2, 0x70, 0xf3, 0x15, 0x18, 0x5f, 0x16, 0x47, 0x8e, 0x9c, 0x88, 0x8c,
	0x77, 0xe1, 0xc9, 0xd0, 0x41, 0xd0, 0x98, 0x78, 0x69, 0xfa, 0xfd, 0x93, 0x7c, 0x7e, 0xed, 0x0f,
	0x5d, 0xa5, 0x81, 0x88, 0xbd, 0xc0, 0x0d, 0xb9, 0xf5, 0x7c, 0x6d, 0x4d, 0xac, 0xbd, 0x4c, 0xa7,
	0x63, 0x9a, 0xc8, 0xf3, 0x69, 0x48, 0xa7, 0x8c, 0x72, 0x73, 0x1c, 0x8b, 0x54, 0xe0, 0x7f, 0x32,
	0x38, 0x3d, 0x66, 0x82, 0x09, 0xe9, 0x58, 0x9b, 0x5b, 0x1e, 0x36, 0xdf, 0x20, 0x2a, 0xde, 0xcb,
	0x36, 0xbe, 0x45, 0x4a, 0xe8, 0x6b, 0x50, 0x87, 0x46, 0xd9, 0x6e, 0x67, 0xcb, 0x86, 0xd2, 0xed,
	0x7c, 0x2e, 0x1b, 0xe7, 0x2c, 0x4c, 0x47, 0xee, 0xc0, 0xf4, 0x44, 0xf4, 0x9d, 0x15, 0x88, 0x98,
	0x0b, 0x9f, 0x5a, 0x9e, 0x88, 0x22, 0xc1, 0xcd, 0xde, 0xa4, 0xdb, 0x71, 0x94, 0xd0, 0xc7, 0x67,
	0xa8, 0xb0, 0xc1, 0x69, 0x8a, 0x0e, 0x8d, 0x83, 0x56, 0xdd, 0x94, 0x6c, 0x33, 0x27, 0xf4, 0xa6,
	0x63, 0xea, 0xc8, 0x18, 0x6b, 0xa8, 0x14, 0xd1, 0x68, 0x40, 0xe3, 0x44, 0x53, 0x75, 0xd5, 0x28,
	0x3b, 0x3b, 0xd9, 0xec, 0xa1, 0x4a, 0xde, 0xb6, 0x47, 0xc2, 0x1b, 0xe2, 0x13, 0x54, 0x0c, 0x68,
	0xc8, 0x82, 0x54, 0x0e, 0xa6, 0x3a, 0x5b, 0x85, 0x2f, 0x51, 0x29, 0x7f, 0x64, 0xa2, 0x15, 0x74,
	0xd5, 0xa8, 0xb4, 0xaa, 0x3f, 0x50, 0x76, 0x61, 0xb6, 0x6c, 0x00, 0x67, 0xd7, 0xb9, 0xb8, 0x43,
	0x68, 0x3f, 0x03, 0xae, 0xa3, 0x6a, 0x9f, 0x0f, 0xb9, 0x78, 0xe1, 0xb9, 0x59, 0x03, 0xb8, 0x86,
	0xfe, 0xdf, 0x24, 0xcc, 0x8d, 0xfd, 0xad, 0x03, 0xf1, 0x11, 0x3a, 0x7c, 0x60, 0xcc, 0x8f, 0xdd,
	0x24, 0x1c, 0x6d, 0x4d, 0xc5, 0xee, 0xcf, 0x56, 0x04, 0x2c, 0x56, 0x04, 0xbc, 0x66, 0x04, 0xcc,
	0x32, 0x02, 0xe7, 0x19, 0x81, 0x1f, 0x19, 0x81, 0xef, 0x6b, 0x02, 0xe6, 0x6b, 0x02, 0x16, 0x6b,
	0x02, 0x1e, 0xad, 0xbf, 0xff, 0xec, 0xd7, 0xd2, 0x06, 0x45, 0xb9, 0x8c, 0xf6, 0x57, 0x00, 0x00,
	0x00, 0xff, 0xff, 0xe8, 0x3b, 0x82, 0x18, 0xdd, 0x01, 0x00, 0x00,
}

func (m *Keygen) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Keygen) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Keygen) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Members) > 0 {
		for iNdEx := len(m.Members) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Members[iNdEx])
			copy(dAtA[i:], m.Members[iNdEx])
			i = encodeVarintTypeKeygen(dAtA, i, uint64(len(m.Members[iNdEx])))
			i--
			dAtA[i] = 0x1a
		}
	}
	if m.Type != 0 {
		i = encodeVarintTypeKeygen(dAtA, i, uint64(m.Type))
		i--
		dAtA[i] = 0x10
	}
	if len(m.ID) > 0 {
		i -= len(m.ID)
		copy(dAtA[i:], m.ID)
		i = encodeVarintTypeKeygen(dAtA, i, uint64(len(m.ID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *KeygenBlock) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *KeygenBlock) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *KeygenBlock) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Keygens) > 0 {
		for iNdEx := len(m.Keygens) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Keygens[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintTypeKeygen(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x22
		}
	}
	if m.Height != 0 {
		i = encodeVarintTypeKeygen(dAtA, i, uint64(m.Height))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintTypeKeygen(dAtA []byte, offset int, v uint64) int {
	offset -= sovTypeKeygen(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Keygen) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ID)
	if l > 0 {
		n += 1 + l + sovTypeKeygen(uint64(l))
	}
	if m.Type != 0 {
		n += 1 + sovTypeKeygen(uint64(m.Type))
	}
	if len(m.Members) > 0 {
		for _, s := range m.Members {
			l = len(s)
			n += 1 + l + sovTypeKeygen(uint64(l))
		}
	}
	return n
}

func (m *KeygenBlock) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Height != 0 {
		n += 1 + sovTypeKeygen(uint64(m.Height))
	}
	if len(m.Keygens) > 0 {
		for _, e := range m.Keygens {
			l = e.Size()
			n += 1 + l + sovTypeKeygen(uint64(l))
		}
	}
	return n
}

func sovTypeKeygen(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozTypeKeygen(x uint64) (n int) {
	return sovTypeKeygen(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Keygen) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypeKeygen
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Keygen: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Keygen: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypeKeygen
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTypeKeygen
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTypeKeygen
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ID = gitlab_com_thorchain_thornode_common.TxID(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			m.Type = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypeKeygen
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Type |= KeygenType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Members", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypeKeygen
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTypeKeygen
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTypeKeygen
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Members = append(m.Members, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypeKeygen(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTypeKeygen
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTypeKeygen
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *KeygenBlock) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypeKeygen
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: KeygenBlock: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: KeygenBlock: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Height", wireType)
			}
			m.Height = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypeKeygen
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Height |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Keygens", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypeKeygen
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypeKeygen
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypeKeygen
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Keygens = append(m.Keygens, Keygen{})
			if err := m.Keygens[len(m.Keygens)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypeKeygen(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTypeKeygen
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTypeKeygen
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipTypeKeygen(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTypeKeygen
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTypeKeygen
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTypeKeygen
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthTypeKeygen
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupTypeKeygen
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthTypeKeygen
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthTypeKeygen        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTypeKeygen          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupTypeKeygen = fmt.Errorf("proto: unexpected end of group")
)
