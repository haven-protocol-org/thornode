package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	"gitlab.com/thorchain/bepswap/thornode/common"
)

// MaxWithdrawBasisPoints
const MaxWithdrawBasisPoints = 10000

// MsgSetUnStake is used to withdraw
type MsgSetUnStake struct {
	RuneAddress         common.Address `json:"rune_address"`          // it should be the rune address
	WithdrawBasisPoints sdk.Uint       `json:"withdraw_basis_points"` // withdraw basis points
	Asset               common.Asset   `json:"asset"`                 // asset asset asset
	RequestTxHash       common.TxID    `json:"request_tx_hash"`       // request tx hash on chain
	Signer              sdk.AccAddress `json:"signer"`
}

// NewMsgSetUnStake is a constructor function for MsgSetPoolData
func NewMsgSetUnStake(runeAddress common.Address, withdrawBasisPoints sdk.Uint, asset common.Asset, requestTxHash common.TxID, signer sdk.AccAddress) MsgSetUnStake {
	return MsgSetUnStake{
		RuneAddress:         runeAddress,
		WithdrawBasisPoints: withdrawBasisPoints,
		Asset:               asset,
		RequestTxHash:       requestTxHash,
		Signer:              signer,
	}
}

// Route should return the pooldata of the module
func (msg MsgSetUnStake) Route() string { return RouterKey }

// Type should return the action
func (msg MsgSetUnStake) Type() string { return "set_unstake" }

// ValidateBasic runs stateless checks on the message
func (msg MsgSetUnStake) ValidateBasic() sdk.Error {
	if msg.Signer.Empty() {
		return sdk.ErrInvalidAddress(msg.Signer.String())
	}
	if msg.Asset.IsEmpty() {
		return sdk.ErrUnknownRequest("Pool Asset cannot be empty")
	}
	if msg.RuneAddress.IsEmpty() {
		return sdk.ErrUnknownRequest("Address cannot be empty")
	}
	if !msg.RuneAddress.IsChain(common.BNBChain) {
		return sdk.ErrUnknownRequest("Address must be a BNB address")
	}
	if msg.RequestTxHash.IsEmpty() {
		return sdk.ErrUnknownRequest("request tx hash cannot be empty")
	}
	if msg.WithdrawBasisPoints.IsZero() {
		return sdk.ErrUnknownRequest("WithdrawBasicPoints can't be zero")
	}
	if msg.WithdrawBasisPoints.GT(sdk.ZeroUint()) && msg.WithdrawBasisPoints.GT(sdk.NewUint(MaxWithdrawBasisPoints)) {
		return sdk.ErrUnknownRequest("WithdrawBasisPoints is larger than maximum withdraw basis points")
	}
	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgSetUnStake) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgSetUnStake) GetSigners() []sdk.AccAddress {
	return []sdk.AccAddress{msg.Signer}
}