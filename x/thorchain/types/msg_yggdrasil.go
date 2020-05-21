package types

import (
	"gitlab.com/thorchain/thornode/common"
	cosmos "gitlab.com/thorchain/thornode/common/cosmos"
)

// MsgYggdrasil defines a MsgYggdrasil message
type MsgYggdrasil struct {
	Tx          common.Tx         `json:"tx"`
	PubKey      common.PubKey     `json:"pub_key"`
	AddFunds    bool              `json:"add_funds"`
	Coins       common.Coins      `json:"coins"`
	BlockHeight int64             `json:"block_height"`
	Signer      cosmos.AccAddress `json:"signer"`
}

// NewMsgYggdrasil is a constructor function for MsgYggdrasil
func NewMsgYggdrasil(tx common.Tx, pk common.PubKey, blockHeight int64, addFunds bool, coins common.Coins, signer cosmos.AccAddress) MsgYggdrasil {
	return MsgYggdrasil{
		Tx:          tx,
		PubKey:      pk,
		AddFunds:    addFunds,
		Coins:       coins,
		BlockHeight: blockHeight,
		Signer:      signer,
	}
}

func (msg MsgYggdrasil) Route() string { return RouterKey }

func (msg MsgYggdrasil) Type() string { return "set_yggdrasil" }

// ValidateBasic runs stateless checks on the message
func (msg MsgYggdrasil) ValidateBasic() error {
	if msg.Signer.Empty() {
		return cosmos.ErrInvalidAddress(msg.Signer.String())
	}
	if msg.PubKey.IsEmpty() {
		return cosmos.ErrUnknownRequest("pubkey cannot be empty")
	}
	if msg.BlockHeight <= 0 {
		return cosmos.ErrUnknownRequest("invalid block height")
	}
	if msg.Tx.IsEmpty() {
		return cosmos.ErrUnknownRequest("request tx cannot be empty")
	}
	for _, coin := range msg.Coins {
		if err := coin.IsValid(); err != nil {
			return cosmos.ErrInvalidCoins(err.Error())
		}
	}
	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgYggdrasil) GetSignBytes() []byte {
	return cosmos.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgYggdrasil) GetSigners() []cosmos.AccAddress {
	return []cosmos.AccAddress{msg.Signer}
}
