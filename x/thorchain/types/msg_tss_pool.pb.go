// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: thorchain/v1/x/thorchain/types/msg_tss_pool.proto

package types

import (
	fmt "fmt"
	github_com_cosmos_cosmos_sdk_types "github.com/cosmos/cosmos-sdk/types"
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

type MsgTssPool struct {
	ID             string                                        `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	PoolPubKey     gitlab_com_thorchain_thornode_common.PubKey   `protobuf:"bytes,2,opt,name=pool_pub_key,json=poolPubKey,proto3,casttype=gitlab.com/thorchain/thornode/common.PubKey" json:"pool_pub_key,omitempty"`
	KeygenType     KeygenType                                    `protobuf:"varint,3,opt,name=keygen_type,json=keygenType,proto3,enum=types.KeygenType,casttype=KeygenType" json:"keygen_type,omitempty"`
	PubKeys        []string                                      `protobuf:"bytes,4,rep,name=pub_keys,json=pubKeys,proto3" json:"pub_keys,omitempty"`
	Height         int64                                         `protobuf:"varint,5,opt,name=height,proto3" json:"height,omitempty"`
	Blame          Blame                                         `protobuf:"bytes,6,opt,name=blame,proto3" json:"blame"`
	Chains         []string                                      `protobuf:"bytes,7,rep,name=chains,proto3" json:"chains,omitempty"`
	Signer         github_com_cosmos_cosmos_sdk_types.AccAddress `protobuf:"bytes,8,opt,name=signer,proto3,casttype=github.com/cosmos/cosmos-sdk/types.AccAddress" json:"signer,omitempty"`
	KeygenTime     int64                                         `protobuf:"varint,9,opt,name=keygen_time,json=keygenTime,proto3" json:"keygen_time,omitempty"`
	CryptonoteData string
}

func (m *MsgTssPool) Reset()         { *m = MsgTssPool{} }
func (m *MsgTssPool) String() string { return proto.CompactTextString(m) }
func (*MsgTssPool) ProtoMessage()    {}
func (*MsgTssPool) Descriptor() ([]byte, []int) {
	return fileDescriptor_32aba2b7bcac22c3, []int{0}
}
func (m *MsgTssPool) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MsgTssPool) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MsgTssPool.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MsgTssPool) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MsgTssPool.Merge(m, src)
}
func (m *MsgTssPool) XXX_Size() int {
	return m.Size()
}
func (m *MsgTssPool) XXX_DiscardUnknown() {
	xxx_messageInfo_MsgTssPool.DiscardUnknown(m)
}

var xxx_messageInfo_MsgTssPool proto.InternalMessageInfo

func init() {
	proto.RegisterType((*MsgTssPool)(nil), "types.MsgTssPool")
}

func init() {
	proto.RegisterFile("thorchain/v1/x/thorchain/types/msg_tss_pool.proto", fileDescriptor_32aba2b7bcac22c3)
}

var fileDescriptor_32aba2b7bcac22c3 = []byte{
	// 426 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0x41, 0x6f, 0x9b, 0x30,
	0x18, 0xc5, 0x49, 0x43, 0x1b, 0x37, 0xaa, 0x34, 0x6b, 0xaa, 0xbc, 0x1e, 0x00, 0xed, 0x84, 0x34,
	0x15, 0x2f, 0xdd, 0x2f, 0x28, 0xda, 0xa5, 0xaa, 0x2a, 0x75, 0xa8, 0xa7, 0x5d, 0x50, 0x00, 0xcb,
	0x58, 0x09, 0x18, 0xf1, 0x91, 0x69, 0xf9, 0x17, 0xfb, 0x01, 0xfb, 0x41, 0x39, 0xe6, 0xb8, 0x13,
	0xda, 0xc8, 0xbf, 0xc8, 0x69, 0xb2, 0x61, 0xcb, 0xa4, 0x49, 0x5b, 0x2f, 0xf0, 0x9e, 0xed, 0xf7,
	0x78, 0x7e, 0x1f, 0x78, 0xde, 0xe4, 0xaa, 0x4e, 0xf3, 0x85, 0x2c, 0xd9, 0xa7, 0x39, 0xfb, 0xcc,
	0x8e, 0xb4, 0xd9, 0x54, 0x1c, 0x58, 0x01, 0x22, 0x6e, 0x00, 0xe2, 0x4a, 0xa9, 0x55, 0x50, 0xd5,
	0xaa, 0x51, 0x64, 0x62, 0x76, 0xae, 0xd8, 0x7f, 0x94, 0xfa, 0x19, 0x27, 0xab, 0x45, 0xc1, 0x7b,
	0xdd, 0xd5, 0xdb, 0xe7, 0x08, 0x96, 0x7c, 0x23, 0x78, 0x39, 0x28, 0x5e, 0x0a, 0x25, 0x94, 0x81,
	0x4c, 0xa3, 0x7e, 0xf5, 0xf5, 0xd7, 0x31, 0xc6, 0x0f, 0x20, 0x9e, 0x00, 0x1e, 0x95, 0x5a, 0x91,
	0x4b, 0x3c, 0x92, 0x19, 0x45, 0x1e, 0xf2, 0xa7, 0xa1, 0xdd, 0xb5, 0xee, 0xe8, 0xee, 0x7d, 0x34,
	0x92, 0x19, 0xf9, 0x80, 0x67, 0x3a, 0x74, 0x5c, 0xad, 0x13, 0xed, 0x4a, 0x47, 0xe6, 0x04, 0x3b,
	0xb4, 0xee, 0x1b, 0x21, 0x9b, 0xd5, 0x22, 0x09, 0x52, 0x55, 0xfc, 0x19, 0x22, 0x57, 0x75, 0xa9,
	0x32, 0xce, 0x52, 0x55, 0x14, 0xaa, 0x0c, 0x1e, 0xd7, 0xc9, 0x3d, 0xdf, 0x44, 0x58, 0x9b, 0xf4,
	0x98, 0x84, 0xf8, 0xbc, 0xcf, 0x17, 0xeb, 0xac, 0x74, 0xec, 0x21, 0xff, 0xe2, 0xe6, 0x45, 0x60,
	0xe2, 0x07, 0xf7, 0x66, 0xe7, 0x69, 0x53, 0xf1, 0xf0, 0xe2, 0xd0, 0xba, 0xf8, 0xc8, 0x23, 0xbc,
	0xfc, 0x8d, 0xc9, 0x2b, 0x7c, 0x36, 0x24, 0x02, 0x7a, 0xe2, 0x8d, 0xfd, 0x69, 0x74, 0x5a, 0x19,
	0x77, 0x20, 0x97, 0xd8, 0xce, 0xb9, 0x14, 0x79, 0x43, 0x27, 0x1e, 0xf2, 0xc7, 0xd1, 0xc0, 0x88,
	0x8f, 0x27, 0xa6, 0x47, 0x6a, 0x7b, 0xc8, 0x3f, 0xbf, 0x99, 0x0d, 0x1f, 0x0c, 0xf5, 0x5a, 0x78,
	0xb2, 0x6d, 0x5d, 0x2b, 0xea, 0x0f, 0x68, 0x07, 0x73, 0x19, 0xa0, 0xa7, 0xc6, 0x7a, 0x60, 0xe4,
	0x0e, 0xdb, 0x20, 0x45, 0xc9, 0x6b, 0x7a, 0xe6, 0x21, 0x7f, 0x16, 0xce, 0x0f, 0xad, 0x7b, 0x2d,
	0x64, 0x93, 0xaf, 0xfb, 0x16, 0x52, 0x05, 0x85, 0x82, 0xe1, 0x75, 0x0d, 0xd9, 0xb2, 0x1f, 0x49,
	0x70, 0x9b, 0xa6, 0xb7, 0x59, 0x56, 0x73, 0x80, 0x68, 0x30, 0x20, 0xee, 0xb1, 0x03, 0x59, 0x70,
	0x3a, 0x35, 0x49, 0x7f, 0x5d, 0x50, 0x16, 0x3c, 0x7c, 0xd8, 0xfe, 0x70, 0xac, 0x6d, 0xe7, 0xa0,
	0x5d, 0xe7, 0xa0, 0xef, 0x9d, 0x83, 0xbe, 0xec, 0x1d, 0x6b, 0xb7, 0x77, 0xac, 0x6f, 0x7b, 0xc7,
	0xfa, 0xc8, 0xfe, 0xdd, 0xfd, 0x5f, 0x7f, 0x45, 0x62, 0x9b, 0xa1, 0xbf, 0xfb, 0x19, 0x00, 0x00,
	0xff, 0xff, 0x63, 0xec, 0xc5, 0x71, 0xa9, 0x02, 0x00, 0x00,
}

func (m *MsgTssPool) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MsgTssPool) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MsgTssPool) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.KeygenTime != 0 {
		i = encodeVarintMsgTssPool(dAtA, i, uint64(m.KeygenTime))
		i--
		dAtA[i] = 0x48
	}
	if len(m.Signer) > 0 {
		i -= len(m.Signer)
		copy(dAtA[i:], m.Signer)
		i = encodeVarintMsgTssPool(dAtA, i, uint64(len(m.Signer)))
		i--
		dAtA[i] = 0x42
	}
	if len(m.Chains) > 0 {
		for iNdEx := len(m.Chains) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Chains[iNdEx])
			copy(dAtA[i:], m.Chains[iNdEx])
			i = encodeVarintMsgTssPool(dAtA, i, uint64(len(m.Chains[iNdEx])))
			i--
			dAtA[i] = 0x3a
		}
	}
	{
		size, err := m.Blame.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintMsgTssPool(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x32
	if m.Height != 0 {
		i = encodeVarintMsgTssPool(dAtA, i, uint64(m.Height))
		i--
		dAtA[i] = 0x28
	}
	if len(m.PubKeys) > 0 {
		for iNdEx := len(m.PubKeys) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.PubKeys[iNdEx])
			copy(dAtA[i:], m.PubKeys[iNdEx])
			i = encodeVarintMsgTssPool(dAtA, i, uint64(len(m.PubKeys[iNdEx])))
			i--
			dAtA[i] = 0x22
		}
	}
	if m.KeygenType != 0 {
		i = encodeVarintMsgTssPool(dAtA, i, uint64(m.KeygenType))
		i--
		dAtA[i] = 0x18
	}
	if len(m.PoolPubKey) > 0 {
		i -= len(m.PoolPubKey)
		copy(dAtA[i:], m.PoolPubKey)
		i = encodeVarintMsgTssPool(dAtA, i, uint64(len(m.PoolPubKey)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.ID) > 0 {
		i -= len(m.ID)
		copy(dAtA[i:], m.ID)
		i = encodeVarintMsgTssPool(dAtA, i, uint64(len(m.ID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintMsgTssPool(dAtA []byte, offset int, v uint64) int {
	offset -= sovMsgTssPool(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *MsgTssPool) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ID)
	if l > 0 {
		n += 1 + l + sovMsgTssPool(uint64(l))
	}
	l = len(m.PoolPubKey)
	if l > 0 {
		n += 1 + l + sovMsgTssPool(uint64(l))
	}
	if m.KeygenType != 0 {
		n += 1 + sovMsgTssPool(uint64(m.KeygenType))
	}
	if len(m.PubKeys) > 0 {
		for _, s := range m.PubKeys {
			l = len(s)
			n += 1 + l + sovMsgTssPool(uint64(l))
		}
	}
	if m.Height != 0 {
		n += 1 + sovMsgTssPool(uint64(m.Height))
	}
	l = m.Blame.Size()
	n += 1 + l + sovMsgTssPool(uint64(l))
	if len(m.Chains) > 0 {
		for _, s := range m.Chains {
			l = len(s)
			n += 1 + l + sovMsgTssPool(uint64(l))
		}
	}
	l = len(m.Signer)
	if l > 0 {
		n += 1 + l + sovMsgTssPool(uint64(l))
	}
	if m.KeygenTime != 0 {
		n += 1 + sovMsgTssPool(uint64(m.KeygenTime))
	}
	return n
}

func sovMsgTssPool(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMsgTssPool(x uint64) (n int) {
	return sovMsgTssPool(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *MsgTssPool) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMsgTssPool
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
			return fmt.Errorf("proto: MsgTssPool: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MsgTssPool: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgTssPool
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
				return ErrInvalidLengthMsgTssPool
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMsgTssPool
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PoolPubKey", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgTssPool
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
				return ErrInvalidLengthMsgTssPool
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMsgTssPool
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PoolPubKey = gitlab_com_thorchain_thornode_common.PubKey(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field KeygenType", wireType)
			}
			m.KeygenType = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgTssPool
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.KeygenType |= KeygenType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PubKeys", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgTssPool
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
				return ErrInvalidLengthMsgTssPool
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMsgTssPool
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PubKeys = append(m.PubKeys, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Height", wireType)
			}
			m.Height = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgTssPool
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
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Blame", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgTssPool
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
				return ErrInvalidLengthMsgTssPool
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthMsgTssPool
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Blame.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Chains", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgTssPool
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
				return ErrInvalidLengthMsgTssPool
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMsgTssPool
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Chains = append(m.Chains, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 8:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Signer", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgTssPool
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMsgTssPool
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMsgTssPool
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Signer = append(m.Signer[:0], dAtA[iNdEx:postIndex]...)
			if m.Signer == nil {
				m.Signer = []byte{}
			}
			iNdEx = postIndex
		case 9:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field KeygenTime", wireType)
			}
			m.KeygenTime = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgTssPool
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.KeygenTime |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipMsgTssPool(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMsgTssPool
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthMsgTssPool
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
func skipMsgTssPool(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMsgTssPool
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
					return 0, ErrIntOverflowMsgTssPool
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
					return 0, ErrIntOverflowMsgTssPool
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
				return 0, ErrInvalidLengthMsgTssPool
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMsgTssPool
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMsgTssPool
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMsgTssPool        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMsgTssPool          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMsgTssPool = fmt.Errorf("proto: unexpected end of group")
)
