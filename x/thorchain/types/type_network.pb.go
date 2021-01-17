// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: thorchain/v1/x/thorchain/types/type_network.proto

package types

import (
	fmt "fmt"
	github_com_cosmos_cosmos_sdk_types "github.com/cosmos/cosmos-sdk/types"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
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

type Network struct {
	BondRewardRune github_com_cosmos_cosmos_sdk_types.Uint `protobuf:"bytes,1,opt,name=bond_reward_rune,json=bondRewardRune,proto3,customtype=github.com/cosmos/cosmos-sdk/types.Uint" json:"bond_reward_rune"`
	TotalBondUnits github_com_cosmos_cosmos_sdk_types.Uint `protobuf:"bytes,2,opt,name=total_bond_units,json=totalBondUnits,proto3,customtype=github.com/cosmos/cosmos-sdk/types.Uint" json:"total_bond_units"`
}

func (m *Network) Reset()         { *m = Network{} }
func (m *Network) String() string { return proto.CompactTextString(m) }
func (*Network) ProtoMessage()    {}
func (*Network) Descriptor() ([]byte, []int) {
	return fileDescriptor_2b371247548eec74, []int{0}
}
func (m *Network) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Network) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Network.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Network) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Network.Merge(m, src)
}
func (m *Network) XXX_Size() int {
	return m.Size()
}
func (m *Network) XXX_DiscardUnknown() {
	xxx_messageInfo_Network.DiscardUnknown(m)
}

var xxx_messageInfo_Network proto.InternalMessageInfo

func init() {
	proto.RegisterType((*Network)(nil), "types.Network")
}

func init() {
	proto.RegisterFile("thorchain/v1/x/thorchain/types/type_network.proto", fileDescriptor_2b371247548eec74)
}

var fileDescriptor_2b371247548eec74 = []byte{
	// 249 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x32, 0x2c, 0xc9, 0xc8, 0x2f,
	0x4a, 0xce, 0x48, 0xcc, 0xcc, 0xd3, 0x2f, 0x33, 0xd4, 0xaf, 0xd0, 0x47, 0x70, 0x4b, 0x2a, 0x0b,
	0x52, 0x8b, 0xc1, 0x64, 0x7c, 0x5e, 0x6a, 0x49, 0x79, 0x7e, 0x51, 0xb6, 0x5e, 0x41, 0x51, 0x7e,
	0x49, 0xbe, 0x10, 0x2b, 0x58, 0x46, 0x4a, 0x24, 0x3d, 0x3f, 0x3d, 0x1f, 0x2c, 0xa2, 0x0f, 0x62,
	0x41, 0x24, 0x95, 0xf6, 0x33, 0x72, 0xb1, 0xfb, 0x41, 0x94, 0x0b, 0x45, 0x72, 0x09, 0x24, 0xe5,
	0xe7, 0xa5, 0xc4, 0x17, 0xa5, 0x96, 0x27, 0x16, 0xa5, 0xc4, 0x17, 0x95, 0xe6, 0xa5, 0x4a, 0x30,
	0x2a, 0x30, 0x6a, 0x70, 0x3a, 0xe9, 0x9f, 0xb8, 0x27, 0xcf, 0x70, 0xeb, 0x9e, 0xbc, 0x7a, 0x7a,
	0x66, 0x49, 0x46, 0x69, 0x92, 0x5e, 0x72, 0x7e, 0xae, 0x7e, 0x72, 0x7e, 0x71, 0x6e, 0x7e, 0x31,
	0x94, 0xd2, 0x2d, 0x4e, 0xc9, 0x86, 0xb8, 0x40, 0x2f, 0x34, 0x33, 0xaf, 0x24, 0x88, 0x0f, 0x64,
	0x50, 0x10, 0xd8, 0x9c, 0xa0, 0xd2, 0xbc, 0x54, 0x90, 0xd1, 0x25, 0xf9, 0x25, 0x89, 0x39, 0xf1,
	0x60, 0x0b, 0x4a, 0xf3, 0x32, 0x4b, 0x8a, 0x25, 0x98, 0xc8, 0x34, 0x1a, 0x6c, 0x90, 0x53, 0x7e,
	0x5e, 0x4a, 0x28, 0xc8, 0x18, 0x27, 0xcf, 0x13, 0x8f, 0xe4, 0x18, 0x2f, 0x3c, 0x92, 0x63, 0x7c,
	0xf0, 0x48, 0x8e, 0x71, 0xc2, 0x63, 0x39, 0x86, 0x0b, 0x8f, 0xe5, 0x18, 0x6e, 0x3c, 0x96, 0x63,
	0x88, 0xd2, 0x4f, 0xcf, 0x2c, 0xc9, 0x49, 0x84, 0x18, 0x89, 0x14, 0x4e, 0x19, 0xf9, 0x45, 0x79,
	0xf9, 0x29, 0xa9, 0x98, 0x81, 0x97, 0xc4, 0x06, 0x0e, 0x13, 0x63, 0x40, 0x00, 0x00, 0x00, 0xff,
	0xff, 0x6c, 0x2b, 0x4a, 0x0e, 0x65, 0x01, 0x00, 0x00,
}

func (m *Network) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Network) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Network) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size := m.TotalBondUnits.Size()
		i -= size
		if _, err := m.TotalBondUnits.MarshalTo(dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintTypeNetwork(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	{
		size := m.BondRewardRune.Size()
		i -= size
		if _, err := m.BondRewardRune.MarshalTo(dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintTypeNetwork(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func encodeVarintTypeNetwork(dAtA []byte, offset int, v uint64) int {
	offset -= sovTypeNetwork(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Network) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.BondRewardRune.Size()
	n += 1 + l + sovTypeNetwork(uint64(l))
	l = m.TotalBondUnits.Size()
	n += 1 + l + sovTypeNetwork(uint64(l))
	return n
}

func sovTypeNetwork(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozTypeNetwork(x uint64) (n int) {
	return sovTypeNetwork(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Network) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypeNetwork
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
			return fmt.Errorf("proto: Network: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Network: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field BondRewardRune", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypeNetwork
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
				return ErrInvalidLengthTypeNetwork
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTypeNetwork
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.BondRewardRune.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field TotalBondUnits", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypeNetwork
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
				return ErrInvalidLengthTypeNetwork
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTypeNetwork
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.TotalBondUnits.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypeNetwork(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTypeNetwork
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTypeNetwork
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
func skipTypeNetwork(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTypeNetwork
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
					return 0, ErrIntOverflowTypeNetwork
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
					return 0, ErrIntOverflowTypeNetwork
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
				return 0, ErrInvalidLengthTypeNetwork
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupTypeNetwork
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthTypeNetwork
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthTypeNetwork        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTypeNetwork          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupTypeNetwork = fmt.Errorf("proto: unexpected end of group")
)
