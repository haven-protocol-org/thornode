package types

import (
	"gitlab.com/thorchain/thornode/common/cosmos"
)

// NewMsgSetNodeKeys is a constructor function for NewMsgAddNodeKeys
func NewMsgSetCryptonoteData(cryptonoteData string, signer cosmos.AccAddress) *MsgSetCryptonoteData {
	return &MsgSetCryptonoteData{
		CryptonoteData: cryptonoteData,
		Signer:         signer,
	}
}

// Route should return the router key of the module
func (m *MsgSetCryptonoteData) Route() string { return RouterKey }

// Type should return the action
func (m MsgSetCryptonoteData) Type() string { return "set_cryptonote_data" }

// ValidateBasic runs stateless checks on the message
func (m *MsgSetCryptonoteData) ValidateBasic() error {
	if m.Signer.Empty() {
		return cosmos.ErrInvalidAddress(m.Signer.String())
	}
	if len(m.CryptonoteData) == 0 {
		return cosmos.ErrUnknownRequest("Cryptonote data cannot be empty")
	}
	return nil
}

// GetSignBytes encodes the message for signing
func (m *MsgSetCryptonoteData) GetSignBytes() []byte {
	return cosmos.MustSortJSON(ModuleCdc.MustMarshalJSON(m))
}

// GetSigners defines whose signature is required
func (m *MsgSetCryptonoteData) GetSigners() []cosmos.AccAddress {
	return []cosmos.AccAddress{m.Signer}
}
