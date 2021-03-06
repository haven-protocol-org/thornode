package types

import (
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
)

// NewMsgLeave create a new instance of MsgLeave
func NewMsgLeave(tx common.Tx, addr, signer cosmos.AccAddress) *MsgLeave {
	return &MsgLeave{
		Tx:          tx,
		NodeAddress: addr,
		Signer:      signer,
	}
}

// Route should return the router key of the module
func (m *MsgLeave) Route() string { return RouterKey }

// Type should return the action
func (m MsgLeave) Type() string { return "leave" }

// ValidateBasic runs stateless checks on the message
func (m *MsgLeave) ValidateBasic() error {
	if m.Tx.FromAddress.IsEmpty() {
		return cosmos.ErrInvalidAddress("from address cannot be empty")
	}
	if m.Tx.ID.IsEmpty() {
		return cosmos.ErrUnknownRequest("tx id cannot be empty")
	}
	if m.Tx.FromAddress.IsEmpty() {
		return cosmos.ErrInvalidAddress("tx from address cannot be empty")
	}
	if m.Signer.Empty() {
		return cosmos.ErrInvalidAddress("signer cannot be empty ")
	}
	if m.NodeAddress.Empty() {
		return cosmos.ErrInvalidAddress("node address cannot be empty")
	}
	return nil
}

// GetSignBytes encodes the message for signing
func (m *MsgLeave) GetSignBytes() []byte {
	return cosmos.MustSortJSON(ModuleCdc.MustMarshalJSON(m))
}

// GetSigners defines whose signature is required
func (m *MsgLeave) GetSigners() []cosmos.AccAddress {
	return []cosmos.AccAddress{m.Signer}
}
