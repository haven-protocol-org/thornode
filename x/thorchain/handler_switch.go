package thorchain

import (
	"fmt"

	"github.com/blang/semver"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	"gitlab.com/thorchain/thornode/x/thorchain/keeper"
)

// SwitchHandler is to handle Switch message
// MsgSwitch is used to switch from bep2 RUNE to native RUNE
type SwitchHandler struct {
	keeper keeper.Keeper
	mgr    Manager
}

// NewSwitchHandler create new instance of SwitchHandler
func NewSwitchHandler(keeper keeper.Keeper, mgr Manager) SwitchHandler {
	return SwitchHandler{
		keeper: keeper,
		mgr:    mgr,
	}
}

// Run it the main entry point to execute Switch logic
func (h SwitchHandler) Run(ctx cosmos.Context, m cosmos.Msg, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	msg, ok := m.(*MsgSwitch)
	if !ok {
		return nil, errInvalidMessage
	}
	if err := h.validate(ctx, *msg, version); err != nil {
		ctx.Logger().Error("msg switch failed validation", "error", err)
		return nil, err
	}
	result, err := h.handle(ctx, *msg, version, constAccessor)
	if err != nil {
		ctx.Logger().Error("failed to process msg switch", "error", err)
		return nil, err
	}
	return result, err
}

func (h SwitchHandler) validate(ctx cosmos.Context, msg MsgSwitch, version semver.Version) error {
	if version.GTE(semver.MustParse("0.1.0")) {
		return h.validateV1(ctx, msg)
	}
	return errBadVersion
}

func (h SwitchHandler) validateV1(ctx cosmos.Context, msg MsgSwitch) error {
	if err := msg.ValidateBasic(); err != nil {
		return err
	}

	// if we are getting a non-native asset, ensure its signed by an active
	// node account
	if !msg.Tx.Coins[0].IsNative() {
		if !isSignedByActiveNodeAccounts(ctx, h.keeper, msg.GetSigners()) {
			return cosmos.ErrUnauthorized(notAuthorized.Error())
		}
	}

	return nil
}

func (h SwitchHandler) handle(ctx cosmos.Context, msg MsgSwitch, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	ctx.Logger().Info("handleMsgSwitch request", "destination address", msg.Destination.String())
	if version.GTE(semver.MustParse("0.1.0")) {
		return h.handleV1(ctx, msg, version, constAccessor)
	}
	return nil, errBadVersion
}

func (h SwitchHandler) handleV1(ctx cosmos.Context, msg MsgSwitch, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	haltHeight, err := h.keeper.GetMimir(ctx, "HaltTHORChain")
	if err != nil {
		return nil, fmt.Errorf("failed to get mimir setting: %w", err)
	}
	if haltHeight > 0 && common.BlockHeight(ctx) > haltHeight {
		return nil, fmt.Errorf("mimir has halted THORChain transactions")
	}

	if !msg.Tx.Coins[0].IsNative() && msg.Tx.Coins[0].Asset.IsRune() {
		return h.toNative(ctx, msg)
	}

	return nil, fmt.Errorf("only non-native rune can be 'switched' to native rune")
}

func (h SwitchHandler) toNative(ctx cosmos.Context, msg MsgSwitch) (*cosmos.Result, error) {
	coin := common.NewCoin(common.RuneNative, msg.Tx.Coins[0].Amount)

	addr, err := cosmos.AccAddressFromBech32(msg.Destination.String())
	if err != nil {
		return nil, ErrInternal(err, "fail to parse thor address")
	}
	if err := h.keeper.MintAndSendToAccount(ctx, addr, coin); err != nil {
		return nil, ErrInternal(err, "fail to mint native rune coins")
	}

	// update network data
	network, err := h.keeper.GetNetwork(ctx)
	if err != nil {
		// do not cause the transaction to fail
		ctx.Logger().Error("failed to get network", "error", err)
	}

	switch msg.Tx.Chain {
	case common.BNBChain:
		network.BurnedBep2Rune = network.BurnedBep2Rune.Add(coin.Amount)
	case common.ETHChain:
		network.BurnedErc20Rune = network.BurnedErc20Rune.Add(coin.Amount)
	}
	if err := h.keeper.SetNetwork(ctx, network); err != nil {
		ctx.Logger().Error("failed to set network", "error", err)
	}

	return &cosmos.Result{}, nil
}
