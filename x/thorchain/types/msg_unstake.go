package types

import (
	"fmt"

	"gitlab.com/thorchain/thornode/common"
	cosmos "gitlab.com/thorchain/thornode/common/cosmos"
)

// MaxUnstakeBasisPoints
const MaxUnstakeBasisPoints = 10_000

// MsgSetUnStake is used to withdraw
type MsgSetUnStake struct {
	Tx                 common.Tx         `json:"tx"`
	RuneAddress        common.Address    `json:"rune_address"`          // it should be the rune address
	UnstakeBasisPoints cosmos.Uint       `json:"withdraw_basis_points"` // withdraw basis points
	Asset              common.Asset      `json:"asset"`                 // asset asset asset
	Signer             cosmos.AccAddress `json:"signer"`
}

// NewMsgSetUnStake is a constructor function for MsgSetPoolData
func NewMsgSetUnStake(tx common.Tx, runeAddress common.Address, withdrawBasisPoints cosmos.Uint, asset common.Asset, signer cosmos.AccAddress) MsgSetUnStake {
	return MsgSetUnStake{
		Tx:                 tx,
		RuneAddress:        runeAddress,
		UnstakeBasisPoints: withdrawBasisPoints,
		Asset:              asset,
		Signer:             signer,
	}
}

// Route should return the pooldata of the module
func (msg MsgSetUnStake) Route() string { return RouterKey }

// Type should return the action
func (msg MsgSetUnStake) Type() string { return "set_unstake" }

// ValidateBasic runs stateless checks on the message
func (msg MsgSetUnStake) ValidateBasic() error {
	if msg.Signer.Empty() {
		return cosmos.ErrInvalidAddress(msg.Signer.String())
	}
	if err := msg.Tx.IsValid(); err != nil {
		return cosmos.ErrUnknownRequest(err.Error())
	}
	if msg.Asset.IsEmpty() {
		return cosmos.ErrUnknownRequest("Pool Asset cannot be empty")
	}
	if msg.RuneAddress.IsEmpty() {
		return cosmos.ErrUnknownRequest("Address cannot be empty")
	}
	if !msg.RuneAddress.IsChain(common.RuneAsset().Chain) {
		return cosmos.ErrUnknownRequest(fmt.Sprintf("Address must be a %s address", common.RuneAsset().Chain))
	}
	if msg.UnstakeBasisPoints.IsZero() {
		return cosmos.ErrUnknownRequest("UnstakeBasicPoints can't be zero")
	}
	if msg.UnstakeBasisPoints.GT(cosmos.ZeroUint()) && msg.UnstakeBasisPoints.GT(cosmos.NewUint(MaxUnstakeBasisPoints)) {
		return cosmos.ErrUnknownRequest("UnstakeBasisPoints is larger than maximum withdraw basis points")
	}
	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgSetUnStake) GetSignBytes() []byte {
	return cosmos.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgSetUnStake) GetSigners() []cosmos.AccAddress {
	return []cosmos.AccAddress{msg.Signer}
}
