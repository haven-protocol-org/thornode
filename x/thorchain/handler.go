package thorchain

import (
	"fmt"

	"github.com/blang/semver"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	"gitlab.com/thorchain/thornode/x/thorchain/keeper"
)

// MsgHandler is an interface expect all handler to implement
type MsgHandler interface {
	Run(ctx cosmos.Context, msg cosmos.Msg, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error)
}

// NewExternalHandler returns a handler for "thorchain" type messages.
func NewExternalHandler(keeper keeper.Keeper, mgr Manager) cosmos.Handler {
	return func(ctx cosmos.Context, msg cosmos.Msg) (*cosmos.Result, error) {
		ctx = ctx.WithEventManager(cosmos.NewEventManager())
		version := keeper.GetLowestActiveVersion(ctx)
		constantValues := constants.GetConstantValues(version)
		if constantValues == nil {
			return nil, errConstNotAvailable
		}
		handlerMap := getHandlerMapping(keeper, mgr)
		h, ok := handlerMap[msg.Type()]
		if !ok {
			errMsg := fmt.Sprintf("Unrecognized thorchain Msg type: %v", msg.Type())
			return nil, cosmos.ErrUnknownRequest(errMsg)
		}
		result, err := h.Run(ctx, msg, version, constantValues)
		if err != nil {
			return nil, err
		}
		if result == nil {
			result = &cosmos.Result{}
		}
		if len(ctx.EventManager().Events()) > 0 {
			result.Events = ctx.EventManager().ABCIEvents()
		}
		return result, nil
	}
}

func getHandlerMapping(keeper keeper.Keeper, mgr Manager) map[string]MsgHandler {
	// New arch handlers
	m := make(map[string]MsgHandler)

	// consensus handlers
	m[MsgTssPool{}.Type()] = NewTssHandler(keeper, mgr)
	m[MsgObservedTxIn{}.Type()] = NewObservedTxInHandler(keeper, mgr)
	m[MsgObservedTxOut{}.Type()] = NewObservedTxOutHandler(keeper, mgr)
	m[MsgTssKeysignFail{}.Type()] = NewTssKeysignHandler(keeper, mgr)
	m[MsgErrataTx{}.Type()] = NewErrataTxHandler(keeper, mgr)
	m[MsgMimir{}.Type()] = NewMimirHandler(keeper, mgr)
	m[MsgBan{}.Type()] = NewBanHandler(keeper, mgr)
	m[MsgNetworkFee{}.Type()] = NewNetworkFeeHandler(keeper, mgr)

	// cli handlers (non-consensus)
	m[MsgSetNodeKeys{}.Type()] = NewSetNodeKeysHandler(keeper, mgr)
	m[MsgSetVersion{}.Type()] = NewVersionHandler(keeper, mgr)
	m[MsgSetIPAddress{}.Type()] = NewIPAddressHandler(keeper, mgr)
	m[MsgSetCryptonoteData{}.Type()] = NewCryptonoteDataHandler(keeper, mgr)

	// native handlers (non-consensus)
	m[MsgSend{}.Type()] = NewSendHandler(keeper, mgr)
	m[MsgDeposit{}.Type()] = NewDepositHandler(keeper, mgr)
	return m
}

// NewInternalHandler returns a handler for "thorchain" internal type messages.
func NewInternalHandler(keeper keeper.Keeper, mgr Manager) cosmos.Handler {
	return func(ctx cosmos.Context, msg cosmos.Msg) (*cosmos.Result, error) {
		version := keeper.GetLowestActiveVersion(ctx)
		constantValues := constants.GetConstantValues(version)
		if constantValues == nil {
			return nil, errConstNotAvailable
		}
		handlerMap := getInternalHandlerMapping(keeper, mgr)
		h, ok := handlerMap[msg.Type()]
		if !ok {
			errMsg := fmt.Sprintf("Unrecognized thorchain Msg type: %v", msg.Type())
			return nil, cosmos.ErrUnknownRequest(errMsg)
		}
		return h.Run(ctx, msg, version, constantValues)
	}
}

func getInternalHandlerMapping(keeper keeper.Keeper, mgr Manager) map[string]MsgHandler {
	// New arch handlers
	m := make(map[string]MsgHandler)
	m[MsgOutboundTx{}.Type()] = NewOutboundTxHandler(keeper, mgr)
	m[MsgYggdrasil{}.Type()] = NewYggdrasilHandler(keeper, mgr)
	m[MsgSwap{}.Type()] = NewSwapHandler(keeper, mgr)
	m[MsgReserveContributor{}.Type()] = NewReserveContributorHandler(keeper, mgr)
	m[MsgBond{}.Type()] = NewBondHandler(keeper, mgr)
	m[MsgUnBond{}.Type()] = NewUnBondHandler(keeper, mgr)
	m[MsgLeave{}.Type()] = NewLeaveHandler(keeper, mgr)
	m[MsgDonate{}.Type()] = NewDonateHandler(keeper, mgr)
	m[MsgWithdrawLiquidity{}.Type()] = NewWithdrawLiquidityHandler(keeper, mgr)
	m[MsgAddLiquidity{}.Type()] = NewAddLiquidityHandler(keeper, mgr)
	m[MsgRefundTx{}.Type()] = NewRefundHandler(keeper, mgr)
	m[MsgMigrate{}.Type()] = NewMigrateHandler(keeper, mgr)
	m[MsgRagnarok{}.Type()] = NewRagnarokHandler(keeper, mgr)
	m[MsgSwitch{}.Type()] = NewSwitchHandler(keeper, mgr)
	return m
}

func processOneTxIn(ctx cosmos.Context, keeper keeper.Keeper, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	if len(tx.Tx.Coins) == 0 {
		return nil, cosmos.ErrUnknownRequest("no coin found")
	}

	memo, err := ParseMemo(tx.Tx.Memo)
	if err != nil {
		ctx.Logger().Error("fail to parse memo", "error", err)
		return nil, err
	}
	// THORNode should not have one tx across chain, if it is cross chain it should be separate tx
	var newMsg cosmos.Msg
	// interpret the memo and initialize a corresponding msg event
	switch m := memo.(type) {
	case AddLiquidityMemo:
		newMsg, err = getMsgAddLiquidityFromMemo(ctx, m, tx, signer)
	case WithdrawLiquidityMemo:
		newMsg, err = getMsgWithdrawFromMemo(m, tx, signer)
	case SwapMemo:
		newMsg, err = getMsgSwapFromMemo(m, tx, signer)
	case DonateMemo:
		newMsg, err = getMsgDonateFromMemo(m, tx, signer)
	case RefundMemo:
		newMsg, err = getMsgRefundFromMemo(m, tx, signer)
	case OutboundMemo:
		newMsg, err = getMsgOutboundFromMemo(m, tx, signer)
	case MigrateMemo:
		newMsg, err = getMsgMigrateFromMemo(m, tx, signer)
	case BondMemo:
		newMsg, err = getMsgBondFromMemo(m, tx, signer)
	case UnbondMemo:
		newMsg, err = getMsgUnbondFromMemo(m, tx, signer)
	case RagnarokMemo:
		newMsg, err = getMsgRagnarokFromMemo(m, tx, signer)
	case LeaveMemo:
		newMsg, err = getMsgLeaveFromMemo(m, tx, signer)
	case YggdrasilFundMemo:
		newMsg = NewMsgYggdrasil(tx.Tx, tx.ObservedPubKey, m.GetBlockHeight(), true, tx.Tx.Coins, signer)
	case YggdrasilReturnMemo:
		newMsg = NewMsgYggdrasil(tx.Tx, tx.ObservedPubKey, m.GetBlockHeight(), false, tx.Tx.Coins, signer)
	case ReserveMemo:
		res := NewReserveContributor(tx.Tx.FromAddress, tx.Tx.Coins.GetCoin(common.RuneAsset()).Amount)
		newMsg = NewMsgReserveContributor(tx.Tx, res, signer)
	case SwitchMemo:
		newMsg = NewMsgSwitch(tx.Tx, memo.GetDestination(), signer)
	default:
		return nil, errInvalidMemo
	}

	if err != nil {
		return newMsg, err
	}
	return newMsg, newMsg.ValidateBasic()
}

func getMsgSwapFromMemo(memo SwapMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	if memo.Destination.IsEmpty() {
		memo.Destination = tx.Tx.FromAddress
	}
	return NewMsgSwap(tx.Tx, memo.GetAsset(), memo.Destination, memo.SlipLimit, memo.AffiliateAddress, memo.AffiliateBasisPoints, signer), nil
}

func getMsgWithdrawFromMemo(memo WithdrawLiquidityMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	withdrawAmount := cosmos.NewUint(MaxWithdrawBasisPoints)
	if !memo.GetAmount().IsZero() {
		withdrawAmount = memo.GetAmount()
	}
	return NewMsgWithdrawLiquidity(tx.Tx, tx.Tx.FromAddress, withdrawAmount, memo.GetAsset(), memo.GetWithdrawalAsset(), signer), nil
}

func getMsgAddLiquidityFromMemo(ctx cosmos.Context, memo AddLiquidityMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	// Extract the Rune amount and the asset amount from the transaction. At least one of them must be
	// nonzero. If THORNode saw two types of coins, one of them must be the asset coin.
	runeCoin := tx.Tx.Coins.GetCoin(common.RuneAsset())
	assetCoin := tx.Tx.Coins.GetCoin(memo.GetAsset())

	var runeAddr common.Address
	var assetAddr common.Address
	if tx.Tx.Chain.Equals(common.THORChain) {
		runeAddr = tx.Tx.FromAddress
		assetAddr = memo.GetDestination()
	} else {
		runeAddr = memo.GetDestination()
		assetAddr = tx.Tx.FromAddress
	}
	// in case we are providing native rune and another native asset
	if memo.GetAsset().Chain.Equals(common.THORChain) {
		assetAddr = runeAddr
	}

	return NewMsgAddLiquidity(tx.Tx, memo.GetAsset(), runeCoin.Amount, assetCoin.Amount, runeAddr, assetAddr, memo.AffiliateAddress, memo.AffiliateBasisPoints, signer), nil
}

func getMsgDonateFromMemo(memo DonateMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	runeCoin := tx.Tx.Coins.GetCoin(common.RuneAsset())
	assetCoin := tx.Tx.Coins.GetCoin(memo.GetAsset())
	return NewMsgDonate(tx.Tx, memo.GetAsset(), runeCoin.Amount, assetCoin.Amount, signer), nil
}

func getMsgRefundFromMemo(memo RefundMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	return NewMsgRefundTx(tx, memo.GetTxID(), signer), nil
}

func getMsgOutboundFromMemo(memo OutboundMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	return NewMsgOutboundTx(tx, memo.GetTxID(), signer), nil
}

func getMsgMigrateFromMemo(memo MigrateMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	return NewMsgMigrate(tx, memo.GetBlockHeight(), signer), nil
}

func getMsgRagnarokFromMemo(memo RagnarokMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	return NewMsgRagnarok(tx, memo.GetBlockHeight(), signer), nil
}

func getMsgLeaveFromMemo(memo LeaveMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	return NewMsgLeave(tx.Tx, memo.GetAccAddress(), signer), nil
}

func getMsgBondFromMemo(memo BondMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	coin := tx.Tx.Coins.GetCoin(common.RuneAsset())
	return NewMsgBond(tx.Tx, memo.GetAccAddress(), coin.Amount, tx.Tx.FromAddress, signer), nil
}

func getMsgUnbondFromMemo(memo UnbondMemo, tx ObservedTx, signer cosmos.AccAddress) (cosmos.Msg, error) {
	return NewMsgUnBond(tx.Tx, memo.GetAccAddress(), memo.GetAmount(), tx.Tx.FromAddress, signer), nil
}
