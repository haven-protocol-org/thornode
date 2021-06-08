package thorchain

import (
	"fmt"

	"github.com/blang/semver"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
)

// SwapHandler is the handler to process swap request
type SwapHandler struct {
	mgr Manager
}

// NewSwapHandler create a new instance of swap handler
func NewSwapHandler(mgr Manager) SwapHandler {
	return SwapHandler{
		mgr: mgr,
	}
}

// Run is the main entry point of swap message
func (h SwapHandler) Run(ctx cosmos.Context, m cosmos.Msg, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	msg, ok := m.(*MsgSwap)
	if !ok {
		return nil, errInvalidMessage
	}
	if err := h.validate(ctx, *msg, version, constAccessor); err != nil {
		ctx.Logger().Error("MsgSwap failed validation", "error", err)
		return nil, err
	}
	result, err := h.handle(ctx, *msg, version, constAccessor)
	if err != nil {
		ctx.Logger().Error("fail to handle MsgSwap", "error", err)
		return nil, err
	}
	return result, err
}

func (h SwapHandler) validate(ctx cosmos.Context, msg MsgSwap, version semver.Version, constAccessor constants.ConstantValues) error {
	if version.GTE(semver.MustParse("0.55.0")) {
		return h.validateV55(ctx, msg, constAccessor)
	} else if version.GTE(semver.MustParse("0.1.0")) {
		return h.validateV1(ctx, msg, constAccessor)
	}
	return errInvalidVersion
}

func (h SwapHandler) validateV1(ctx cosmos.Context, msg MsgSwap, constAccessor constants.ConstantValues) error {
	return msg.ValidateBasic()
}

func (h SwapHandler) validateV55(ctx cosmos.Context, msg MsgSwap, constAccessor constants.ConstantValues) error {
	return h.validateCurrent(ctx, msg, constAccessor)
}

func (h SwapHandler) validateCurrent(ctx cosmos.Context, msg MsgSwap, constAccessor constants.ConstantValues) error {
	if err := msg.ValidateBasic(); err != nil {
		return err
	}

	target := msg.TargetAsset
	// determine if target is layer1 vs synthetic asset
	if !target.IsRune() && !msg.Destination.IsChain(target.Chain) {
		if msg.Destination.IsChain(common.THORChain) {
			target = target.GetSyntheticAsset()
		} else {
			target = target.GetLayer1Asset()
		}
	}

	if target.IsSyntheticAsset() {

		ensureLiquidityNoLargerThanBond := constAccessor.GetBoolValue(constants.StrictBondLiquidityRatio)
		// the following  only applicable for chaosnet
		totalLiquidityRUNE, err := h.getTotalLiquidityRUNE(ctx)
		if err != nil {
			return ErrInternal(err, "fail to get total liquidity RUNE")
		}

		// total liquidity RUNE after current add liquidity
		if len(msg.Tx.Coins) > 0 {
			// calculate rune value on incoming swap, and add to total liquidity.
			coin := msg.Tx.Coins[0]
			runeVal := coin.Amount
			if !coin.Asset.IsRune() {
				pool, err := h.mgr.Keeper().GetPool(ctx, coin.Asset)
				if err != nil {
					return ErrInternal(err, "fail to get pool")
				}
				runeVal = pool.AssetValueInRune(coin.Amount)
			}
			totalLiquidityRUNE = totalLiquidityRUNE.Add(runeVal)
		}
		maximumLiquidityRune, err := h.mgr.Keeper().GetMimir(ctx, constants.MaximumLiquidityRune.String())
		if maximumLiquidityRune < 0 || err != nil {
			maximumLiquidityRune = constAccessor.GetInt64Value(constants.MaximumLiquidityRune)
		}
		if maximumLiquidityRune > 0 {
			if totalLiquidityRUNE.GT(cosmos.NewUint(uint64(maximumLiquidityRune))) {
				return errAddLiquidityRUNEOverLimit
			}
		}

		if !ensureLiquidityNoLargerThanBond {
			return nil
		}
		totalBondRune, err := h.getTotalActiveBond(ctx)
		if err != nil {
			return ErrInternal(err, "fail to get total bond RUNE")
		}
		if totalLiquidityRUNE.GT(totalBondRune) {
			ctx.Logger().Info(fmt.Sprintf("total liquidity RUNE(%s) is more than total Bond(%s)", totalLiquidityRUNE, totalBondRune))
			return errAddLiquidityRUNEMoreThanBond
		}
	}
	return nil
}

func (h SwapHandler) handle(ctx cosmos.Context, msg MsgSwap, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	ctx.Logger().Info("receive MsgSwap", "request tx hash", msg.Tx.ID, "source asset", msg.Tx.Coins[0].Asset, "target asset", msg.TargetAsset, "signer", msg.Signer.String())
	if version.GTE(semver.MustParse("0.55.0")) {
		return h.handleV55(ctx, msg, version, constAccessor)
	} else if version.GTE(semver.MustParse("0.44.0")) {
		return h.handleV44(ctx, msg, version, constAccessor)
	} else if version.GTE(semver.MustParse("0.43.0")) {
		return h.handleV43(ctx, msg, version, constAccessor)
	} else if version.GTE(semver.MustParse("0.1.0")) {
		return h.handleV1(ctx, msg, version, constAccessor)
	}
	return nil, errBadVersion
}

func (h SwapHandler) handleV1(ctx cosmos.Context, msg MsgSwap, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	transactionFee := h.mgr.GasMgr().GetFee(ctx, msg.Destination.GetChain(), common.RuneAsset())
	synthVirtualDepthMult, err := h.mgr.Keeper().GetMimir(ctx, constants.VirtualMultSynths.String())
	if synthVirtualDepthMult < 1 || err != nil {
		synthVirtualDepthMult = constAccessor.GetInt64Value(constants.VirtualMultSynths)
	}
	swapper := NewSwapperV1()
	_, _, swapErr := swapper.swap(
		ctx,
		h.mgr.Keeper(),
		msg.Tx,
		msg.TargetAsset,
		msg.Destination,
		msg.TradeTarget,
		transactionFee,
		synthVirtualDepthMult,
		h.mgr)
	if swapErr != nil {
		return nil, swapErr
	}
	return &cosmos.Result{}, nil
}

func (h SwapHandler) handleV43(ctx cosmos.Context, msg MsgSwap, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	targetChain := msg.Destination.GetChain()
	if !targetChain.IsValidAddress(msg.Destination) {
		return nil, fmt.Errorf("address(%s) is not valid for chain(%s)", msg.Destination, targetChain)
	}
	transactionFee := h.mgr.GasMgr().GetFee(ctx, msg.Destination.GetChain(), common.RuneAsset())
	synthVirtualDepthMult, err := h.mgr.Keeper().GetMimir(ctx, constants.VirtualMultSynths.String())
	if synthVirtualDepthMult < 1 || err != nil {
		synthVirtualDepthMult = constAccessor.GetInt64Value(constants.VirtualMultSynths)
	}
	swapper := NewSwapperV1()
	_, _, swapErr := swapper.swap(
		ctx,
		h.mgr.Keeper(),
		msg.Tx,
		msg.TargetAsset,
		msg.Destination,
		msg.TradeTarget,
		transactionFee,
		synthVirtualDepthMult,
		h.mgr)
	if swapErr != nil {
		return nil, swapErr
	}
	return &cosmos.Result{}, nil

}

func (h SwapHandler) handleV44(ctx cosmos.Context, msg MsgSwap, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	// test that the network we are running matches the destination network
	if !common.GetCurrentChainNetwork().SoftEquals(msg.Destination.GetNetwork(msg.Destination.GetChain())) {
		return nil, fmt.Errorf("address(%s) is not same network", msg.Destination)
	}
	transactionFee := h.mgr.GasMgr().GetFee(ctx, msg.Destination.GetChain(), common.RuneAsset())
	synthVirtualDepthMult, err := h.mgr.Keeper().GetMimir(ctx, constants.VirtualMultSynths.String())
	if synthVirtualDepthMult < 1 || err != nil {
		synthVirtualDepthMult = constAccessor.GetInt64Value(constants.VirtualMultSynths)
	}
	swapper := NewSwapperV1()
	_, _, swapErr := swapper.swap(
		ctx,
		h.mgr.Keeper(),
		msg.Tx,
		msg.TargetAsset,
		msg.Destination,
		msg.TradeTarget,
		transactionFee,
		synthVirtualDepthMult,
		h.mgr)
	if swapErr != nil {
		return nil, swapErr
	}
	return &cosmos.Result{}, nil

}

func (h SwapHandler) handleV55(ctx cosmos.Context, msg MsgSwap, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	return h.handleCurrent(ctx, msg, version, constAccessor)
}

func (h SwapHandler) handleCurrent(ctx cosmos.Context, msg MsgSwap, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	// test that the network we are running matches the destination network
	if !common.GetCurrentChainNetwork().SoftEquals(msg.Destination.GetNetwork(msg.Destination.GetChain())) {
		return nil, fmt.Errorf("address(%s) is not same network", msg.Destination)
	}
	transactionFee := h.mgr.GasMgr().GetFee(ctx, msg.Destination.GetChain(), common.RuneAsset())
	synthVirtualDepthMult, err := h.mgr.Keeper().GetMimir(ctx, constants.VirtualMultSynths.String())
	if synthVirtualDepthMult < 1 || err != nil {
		synthVirtualDepthMult = constAccessor.GetInt64Value(constants.VirtualMultSynths)
	}
	swapper := NewSwapperV55()
	_, _, swapErr := swapper.swap(
		ctx,
		h.mgr.Keeper(),
		msg.Tx,
		msg.TargetAsset,
		msg.Destination,
		msg.TradeTarget,
		transactionFee,
		synthVirtualDepthMult,
		h.mgr)
	if swapErr != nil {
		return nil, swapErr
	}
	return &cosmos.Result{}, nil
}

// getTotalActiveBond
func (h SwapHandler) getTotalActiveBond(ctx cosmos.Context) (cosmos.Uint, error) {
	nodeAccounts, err := h.mgr.Keeper().ListNodeAccountsWithBond(ctx)
	if err != nil {
		return cosmos.ZeroUint(), err
	}
	total := cosmos.ZeroUint()
	for _, na := range nodeAccounts {
		if na.Status != NodeActive {
			continue
		}
		total = total.Add(na.Bond)
	}
	return total, nil
}

// getTotalLiquidityRUNE we have in all pools
func (h SwapHandler) getTotalLiquidityRUNE(ctx cosmos.Context) (cosmos.Uint, error) {
	pools, err := h.mgr.Keeper().GetPools(ctx)
	if err != nil {
		return cosmos.ZeroUint(), fmt.Errorf("fail to get pools from data store: %w", err)
	}
	total := cosmos.ZeroUint()
	for _, p := range pools {
		// ignore suspended pools
		if p.Status == PoolSuspended {
			continue
		}
		total = total.Add(p.BalanceRune)
	}
	return total, nil
}
