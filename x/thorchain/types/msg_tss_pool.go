package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
)

// NewMsgTssPool is a constructor function for MsgTssPool
func NewMsgTssPool(pks []string, poolpk common.PubKey, cryptonoteData string, KeygenType KeygenType, height int64, bl Blame, chains []string, signer cosmos.AccAddress, keygenTime int64) *MsgTssPool {
	return &MsgTssPool{
		ID:             getTssID(pks, poolpk, height, bl),
		PubKeys:        pks,
		PoolPubKey:     poolpk,
		Height:         height,
		KeygenType:     KeygenType,
		Blame:          bl,
		Chains:         chains,
		Signer:         signer,
		KeygenTime:     keygenTime,
		CryptonoteData: cryptonoteData,
	}
}

// getTssID
func getTssID(members []string, poolPk common.PubKey, height int64, bl Blame) string {
	// ensure input pubkeys list is deterministically sorted
	sort.SliceStable(members, func(i, j int) bool {
		return members[i] < members[j]
	})

	pubkeys := make([]string, len(bl.BlameNodes))
	for i, node := range bl.BlameNodes {
		pubkeys[i] = node.Pubkey
	}
	sort.SliceStable(pubkeys, func(i, j int) bool {
		return pubkeys[i] < pubkeys[j]
	})

	sb := strings.Builder{}
	for _, item := range members {
		sb.WriteString("m:" + item)
	}
	for _, item := range pubkeys {
		sb.WriteString("p:" + item)
	}
	sb.WriteString(poolPk.String())
	sb.WriteString(fmt.Sprintf("%d", height))
	hash := sha256.New()
	return hex.EncodeToString(hash.Sum([]byte(sb.String())))
}

// Route should return the route key of the module
func (m *MsgTssPool) Route() string { return RouterKey }

// Type should return the action
func (m MsgTssPool) Type() string { return "set_tss_pool" }

// ValidateBasic runs stateless checks on the message
func (m *MsgTssPool) ValidateBasic() error {
	if m.Signer.Empty() {
		return cosmos.ErrInvalidAddress(m.Signer.String())
	}
	if len(m.ID) == 0 {
		return cosmos.ErrUnknownRequest("ID cannot be blank")
	}
	if len(m.PubKeys) < 2 {
		return cosmos.ErrUnknownRequest("Must have at least 2 pub keys")
	}
	if len(m.PubKeys) > 100 {
		return cosmos.ErrUnknownRequest("Must have no more then 100 pub keys")
	}
	pks := m.GetPubKeys()
	if len(m.PubKeys) != len(pks) {
		return cosmos.ErrUnknownRequest("One or more pubkeys were not valid")
	}
	for _, pk := range pks {
		if pk.IsEmpty() {
			return cosmos.ErrUnknownRequest("Pubkey cannot be empty")
		}
	}
	// PoolPubKey and cryotonote data can't be empty only when keygen success
	if m.IsSuccess() {
		if m.PoolPubKey.IsEmpty() {
			return cosmos.ErrUnknownRequest("Pool pubkey cannot be empty")
		}
		if len(m.CryptonoteData) != 64 {
			return cosmos.ErrUnknownRequest("Invalid Cryotonote Data")
		}
	}
	// ensure pool pubkey is a valid bech32 pubkey
	if _, err := common.NewPubKey(m.PoolPubKey.String()); err != nil {
		return cosmos.ErrUnknownRequest(err.Error())
	}
	chains := m.GetChains()
	if len(chains) != len(m.Chains) {
		return cosmos.ErrUnknownRequest("One or more chains were not valid")
	}
	if !chains.Has(common.RuneAsset().Chain) {
		return cosmos.ErrUnknownRequest("must support rune asset chain")
	}
	if len(chains) != len(chains.Distinct()) {
		return cosmos.ErrUnknownRequest("cannot have duplicate chains")
	}
	return nil
}

// IsSuccess when blame is empty , then treat it as success
func (m MsgTssPool) IsSuccess() bool {
	return m.Blame.IsEmpty()
}

func (m MsgTssPool) GetChains() common.Chains {
	chains := make(common.Chains, 0)
	for _, c := range m.Chains {
		chain, err := common.NewChain(c)
		if err != nil {
			continue
		}
		chains = append(chains, chain)
	}
	return chains
}

func (m MsgTssPool) GetPubKeys() common.PubKeys {
	pubkeys := make(common.PubKeys, 0)
	for _, pk := range m.PubKeys {
		pk, err := common.NewPubKey(pk)
		if err != nil {
			continue
		}
		pubkeys = append(pubkeys, pk)
	}
	return pubkeys
}

// GetCnData returns the cryotonote data for this message
func (m MsgTssPool) GetCnData() string {
	return m.CryptonoteData
}

// GetSignBytes encodes the message for signing
func (m *MsgTssPool) GetSignBytes() []byte {
	return cosmos.MustSortJSON(ModuleCdc.MustMarshalJSON(m))
}

// GetSigners defines whose signature is required
func (m *MsgTssPool) GetSigners() []cosmos.AccAddress {
	return []cosmos.AccAddress{m.Signer}
}
