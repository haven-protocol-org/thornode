package types

import (
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
)

// NewMsgBond create new MsgBond message
func NewMsgBond(txin common.Tx, nodeAddr cosmos.AccAddress, bond cosmos.Uint, bondAddress common.Address, signer cosmos.AccAddress) *MsgBond {
	return &MsgBond{
		TxIn:        txin,
		NodeAddress: nodeAddr,
		Bond:        bond,
		BondAddress: bondAddress,
		Signer:      signer,
	}
}

// Route should return the router key of the module
func (m *MsgBond) Route() string { return RouterKey }

// Type should return the action
func (m MsgBond) Type() string { return "bond" }

// ValidateBasic runs stateless checks on the message
func (m *MsgBond) ValidateBasic() error {
	if m.NodeAddress.Empty() {
		return cosmos.ErrInvalidAddress("node address cannot be empty")
	}
	if m.Bond.IsZero() {
		return cosmos.ErrUnknownRequest("bond cannot be zero")
	}
	if m.BondAddress.IsEmpty() {
		return cosmos.ErrInvalidAddress("bond address cannot be empty")
	}
	if err := m.TxIn.Valid(); err != nil {
		return cosmos.ErrUnknownRequest(err.Error())
	}
	if len(m.TxIn.Coins) > 1 {
		return cosmos.ErrUnknownRequest("cannot bond more than one coin")
	}
	if len(m.TxIn.Coins) == 0 {
		return cosmos.ErrUnknownRequest("must bond with rune")
	}
	if !m.TxIn.Coins[0].Asset.IsRune() {
		return cosmos.ErrUnknownRequest("cannot bond non-rune asset")
	}
	if m.Signer.Empty() {
		return cosmos.ErrInvalidAddress("empty signer address")
	}
	return nil
}

// GetSignBytes encodes the message for signing
func (m *MsgBond) GetSignBytes() []byte {
	return cosmos.MustSortJSON(ModuleCdc.MustMarshalJSON(m))
}

// GetSigners defines whose signature is required
func (m *MsgBond) GetSigners() []cosmos.AccAddress {
	return []cosmos.AccAddress{m.Signer}
}
