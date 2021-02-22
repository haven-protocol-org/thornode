package thorchain

import (
	"github.com/blang/semver"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	"gitlab.com/thorchain/thornode/x/thorchain/keeper"
)

// withdraw all the asset
// it returns runeAmt,assetAmount,units, lastWithdraw,err
func withdrawV24(ctx cosmos.Context, version semver.Version, keeper keeper.Keeper, msg MsgWithdrawLiquidity, manager Manager) (cosmos.Uint, cosmos.Uint, cosmos.Uint, cosmos.Uint, cosmos.Uint, error) {
	if err := validateWithdrawV1(ctx, keeper, msg); err != nil {
		ctx.Logger().Error("msg withdraw fail validation", "error", err)
		return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), err
	}

	pool, err := keeper.GetPool(ctx, msg.Asset)
	if err != nil {
		ctx.Logger().Error("fail to get pool", "error", err)
		return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), err
	}

	lp, err := keeper.GetLiquidityProvider(ctx, msg.Asset, msg.WithdrawAddress)
	if err != nil {
		ctx.Logger().Error("can't find liquidity provider", "error", err)
		return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), err

	}

	poolUnits := pool.PoolUnits
	poolRune := pool.BalanceRune
	poolAsset := pool.BalanceAsset
	fLiquidityProviderUnit := lp.Units
	if lp.Units.IsZero() {
		if !lp.PendingRune.IsZero() || !lp.PendingAsset.IsZero() {
			keeper.RemoveLiquidityProvider(ctx, lp)
			// remove lp
			return lp.PendingRune, lp.PendingAsset, cosmos.ZeroUint(), lp.Units, cosmos.ZeroUint(), nil
		}
		return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), errNoLiquidityUnitLeft
	}

	cv := constants.GetConstantValues(version)
	height := common.BlockHeight(ctx)
	if height < (lp.LastAddHeight + cv.GetInt64Value(constants.LiquidityLockUpBlocks)) {
		return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), errWithdrawWithin24Hours
	}

	ctx.Logger().Info("pool before withdraw", "pool unit", poolUnits, "balance RUNE", poolRune, "balance asset", poolAsset)
	ctx.Logger().Info("liquidity provider before withdraw", "liquidity provider unit", fLiquidityProviderUnit)

	assetToWithdraw := msg.WithdrawalAsset
	if assetToWithdraw.IsEmpty() {
		// for asymmetric staked lps, need to override the asset
		if lp.RuneAddress.IsEmpty() {
			assetToWithdraw = pool.Asset
		}
		if lp.AssetAddress.IsEmpty() {
			assetToWithdraw = common.RuneAsset()
		}
	}

	// calculate any impermament loss protection or not
	protectionRuneAmount := cosmos.ZeroUint()
	fullProtectionLine, err := keeper.GetMimir(ctx, constants.FullImpLossProtectionBlocks.String())
	if fullProtectionLine < 0 || err != nil {
		fullProtectionLine = cv.GetInt64Value(constants.FullImpLossProtectionBlocks)
	}
	if fullProtectionLine > 0 { // if protection line is zero, no imp loss protection is given
		protectionBasisPoints := calcImpLossProtectionAmtV24(ctx, lp.LastAddHeight, fullProtectionLine)
		protectionRuneAmount = calcImpLossV24(lp, msg.BasisPoints, protectionBasisPoints, pool)
		if !protectionRuneAmount.IsZero() {
			newPoolUnits, extraUnits, err := calculatePoolUnitsV1(poolUnits, poolRune, poolAsset, protectionRuneAmount, cosmos.ZeroUint())
			if err != nil {
				return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), err
			}
			ctx.Logger().Info("liquidity provider granted imp loss protection", "extra provider units", extraUnits, "extra rune", protectionRuneAmount)
			poolRune = poolRune.Add(protectionRuneAmount)
			fLiquidityProviderUnit = fLiquidityProviderUnit.Add(extraUnits)
			poolUnits = newPoolUnits
		}
	}

	withdrawRune, withDrawAsset, unitAfter, err := calculateWithdrawV1(poolUnits, poolRune, poolAsset, fLiquidityProviderUnit, msg.BasisPoints, assetToWithdraw)
	if err != nil {
		ctx.Logger().Error("fail to withdraw", "error", err)
		return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), errWithdrawFail
	}
	if (withdrawRune.Equal(poolRune) && !withDrawAsset.Equal(poolAsset)) || (!withdrawRune.Equal(poolRune) && withDrawAsset.Equal(poolAsset)) {
		ctx.Logger().Error("fail to withdraw: cannot withdraw 100% of only one side of the pool")
		return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), errWithdrawFail
	}
	if version.GTE(semver.MustParse("0.21.0")) {
		withDrawAsset = cosmos.RoundToDecimal(withDrawAsset, pool.Decimals)
	}
	gasAsset := cosmos.ZeroUint()
	// If the pool is empty, and there is a gas asset, subtract required gas
	if common.SafeSub(poolUnits, fLiquidityProviderUnit).Add(unitAfter).IsZero() {
		maxGas, err := manager.GasMgr().GetMaxGas(ctx, pool.Asset.Chain)
		if err != nil {
			ctx.Logger().Error("fail to get gas for asset", "asset", pool.Asset, "error", err)
			return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), errWithdrawFail
		}
		// minus gas costs for our transactions
		// TODO: chain specific logic should be in a single location
		if pool.Asset.IsBNB() && !common.RuneAsset().Chain.Equals(common.THORChain) {
			originalAsset := withDrawAsset
			withDrawAsset = common.SafeSub(
				withDrawAsset,
				maxGas.Amount.MulUint64(2), // RUNE asset is on binance chain
			)
			gasAsset = originalAsset.Sub(withDrawAsset)
		} else if pool.Asset.Chain.GetGasAsset().Equals(pool.Asset) {
			gasAsset = maxGas.Amount
			if gasAsset.GT(withDrawAsset) {
				gasAsset = withDrawAsset
			}
			withDrawAsset = common.SafeSub(withDrawAsset, gasAsset)
		}
	}

	withdrawRune = withdrawRune.Add(lp.PendingRune) // extract pending rune
	lp.PendingRune = cosmos.ZeroUint()              // reset pending to zero

	ctx.Logger().Info("client withdraw", "RUNE", withdrawRune, "asset", withDrawAsset, "units left", unitAfter)
	// update pool
	pool.PoolUnits = common.SafeSub(poolUnits, fLiquidityProviderUnit).Add(unitAfter)
	pool.BalanceRune = common.SafeSub(poolRune, withdrawRune)
	pool.BalanceAsset = common.SafeSub(poolAsset, withDrawAsset)

	ctx.Logger().Info("pool after withdraw", "pool unit", pool.PoolUnits, "balance RUNE", pool.BalanceRune, "balance asset", pool.BalanceAsset)

	lp.LastWithdrawHeight = common.BlockHeight(ctx)
	lp.RuneDepositValue = common.SafeSub(lp.RuneDepositValue, common.GetShare(common.SafeSub(lp.Units, unitAfter), pool.PoolUnits, pool.BalanceRune))
	lp.AssetDepositValue = common.SafeSub(lp.AssetDepositValue, common.GetShare(common.SafeSub(lp.Units, unitAfter), pool.PoolUnits, pool.BalanceAsset))
	lp.Units = unitAfter

	// Create a pool event if THORNode have no rune or assets
	if pool.BalanceAsset.IsZero() || pool.BalanceRune.IsZero() {
		poolEvt := NewEventPool(pool.Asset, PoolStaged)
		if err := manager.EventMgr().EmitEvent(ctx, poolEvt); nil != err {
			ctx.Logger().Error("fail to emit pool event", "error", err)
		}
		pool.Status = PoolStaged
	}

	if err := keeper.SetPool(ctx, pool); err != nil {
		return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), ErrInternal(err, "fail to save pool")
	}
	if keeper.RagnarokInProgress(ctx) {
		keeper.SetLiquidityProvider(ctx, lp)
	} else {
		if !lp.Units.IsZero() {
			keeper.SetLiquidityProvider(ctx, lp)
		} else {
			keeper.RemoveLiquidityProvider(ctx, lp)
		}
	}
	// add rune from the reserve to the asgard module, to cover imp loss protection
	if !protectionRuneAmount.IsZero() {
		err := keeper.SendFromModuleToModule(ctx, ReserveName, AsgardName, common.NewCoins(common.NewCoin(common.RuneAsset(), protectionRuneAmount)))
		if err != nil {
			return cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), cosmos.ZeroUint(), ErrInternal(err, "fail to move imp loss protection rune from the reserve to asgard")
		}
	}
	return withdrawRune, withDrawAsset, protectionRuneAmount, common.SafeSub(fLiquidityProviderUnit, unitAfter), gasAsset, nil
}

// calculate if there needs to add some imp loss protection, in rune
func calcImpLossV24(lp LiquidityProvider, withdrawBasisPoints cosmos.Uint, protectionBasisPoints int64, pool Pool) cosmos.Uint {
	/*
		A0 = assetDepositValue; R0 = runeDepositValue;

		liquidityUnits = units the member wishes to redeem after applying withdrawBasisPoints
		A1 = GetShare(liquidityUnits, poolUnits, assetDepth);
		R1 = GetShare(liquidityUnits, poolUnits, runeDepth);
		P1 = R1/A1
		coverage = (R0 - R1) + (A0 - A1) * P1
	*/

	unitsToClaim := common.GetShare(withdrawBasisPoints, cosmos.NewUint(10000), lp.Units)
	A0 := lp.AssetDepositValue
	R0 := lp.RuneDepositValue
	A1 := common.GetShare(unitsToClaim, pool.PoolUnits, pool.BalanceAsset)
	R1 := common.GetShare(unitsToClaim, pool.PoolUnits, pool.BalanceRune)
	P1 := R1.Quo(A1)
	coverage := common.SafeSub(A0, A1).Mul(P1).Add(common.SafeSub(R0, R1))
	// taking protection basis points, calculate how much of the coverage the user actually receives
	result := coverage.MulUint64(uint64(protectionBasisPoints)).QuoUint64(10000)
	return result
}

// calculate percentage (in basis points) of the amount of impermanent loss protection
func calcImpLossProtectionAmtV24(ctx cosmos.Context, lastDepositHeight, target int64) int64 {
	age := common.BlockHeight(ctx) - lastDepositHeight
	if age < 17280 { // set minimum age to 1 day (17280 blocks)
		return 0
	}
	if age >= target {
		return 10000
	}
	return (age * 10000) / target
}
