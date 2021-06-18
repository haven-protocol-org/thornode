package thorchain

import (
	"fmt"

	"github.com/blang/semver"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
)

// CryptonoteDataHandler is to handle ip address message
type CryptonoteDataHandler struct {
	mgr Manager
}

// NewCryptonoteDataHandler create new instance of CryptonoteDataHandler
func NewCryptonoteDataHandler(mgr Manager) CryptonoteDataHandler {
	return CryptonoteDataHandler{
		mgr: mgr,
	}
}

// Run it the main entry point to execute ip address logic
func (h CryptonoteDataHandler) Run(ctx cosmos.Context, m cosmos.Msg) (*cosmos.Result, error) {
	msg, ok := m.(*MsgSetCryptonoteData)
	if !ok {
		return nil, errInvalidMessage
	}
	ctx.Logger().Info("receive cryotonote data", "data", msg.CryptonoteData)
	if err := h.validate(ctx, *msg); err != nil {
		ctx.Logger().Error("msg set version failed validation", "error", err)
		return nil, err
	}
	if err := h.handle(ctx, *msg); err != nil {
		ctx.Logger().Error("fail to process msg set version", "error", err)
		return nil, err
	}

	return &cosmos.Result{}, nil
}

func (h CryptonoteDataHandler) validate(ctx cosmos.Context, msg MsgSetCryptonoteData) error {
	version := h.mgr.GetVersion()
	if version.GTE(semver.MustParse("0.1.0")) {
		return h.validateV1(ctx, msg)
	}
	return errBadVersion
}

func (h CryptonoteDataHandler) validateV1(ctx cosmos.Context, msg MsgSetCryptonoteData) error {
	return h.validateCurrent(ctx, msg)
}

func (h CryptonoteDataHandler) validateCurrent(ctx cosmos.Context, msg MsgSetCryptonoteData) error {
	if err := msg.ValidateBasic(); err != nil {
		return err
	}

	nodeAccount, err := h.mgr.Keeper().GetNodeAccount(ctx, msg.Signer)
	if err != nil {
		ctx.Logger().Error("fail to get node account", "error", err, "address", msg.Signer.String())
		return cosmos.ErrUnauthorized(fmt.Sprintf("%s is not authorizaed", msg.Signer))
	}
	if nodeAccount.IsEmpty() {
		ctx.Logger().Error("unauthorized account", "address", msg.Signer.String())
		return cosmos.ErrUnauthorized(fmt.Sprintf("%s is not authorizaed", msg.Signer))
	}

	cost, err := h.mgr.Keeper().GetMimir(ctx, constants.NativeTransactionFee.String())
	if err != nil || cost < 0 {
		cost = h.mgr.GetConstants().GetInt64Value(constants.NativeTransactionFee)
	}
	if nodeAccount.Bond.LT(cosmos.NewUint(uint64(cost))) {
		return cosmos.ErrUnauthorized("not enough bond")
	}

	return nil
}

func (h CryptonoteDataHandler) handle(ctx cosmos.Context, msg MsgSetCryptonoteData) error {
	ctx.Logger().Info("handleMsgSetCryptonoteData request", "cryotonote data", msg.CryptonoteData)
	version := h.mgr.GetVersion()
	if version.GTE(semver.MustParse("0.1.0")) {
		return h.handleV1(ctx, msg)
	}
	ctx.Logger().Error(errInvalidVersion.Error())
	return errBadVersion
}

func (h CryptonoteDataHandler) handleV1(ctx cosmos.Context, msg MsgSetCryptonoteData) error {
	return h.handleCurrent(ctx, msg)
}

func (h CryptonoteDataHandler) handleCurrent(ctx cosmos.Context, msg MsgSetCryptonoteData) error {
	nodeAccount, err := h.mgr.Keeper().GetNodeAccount(ctx, msg.Signer)
	if err != nil {
		ctx.Logger().Error("fail to get node account", "error", err, "address", msg.Signer.String())
		return cosmos.ErrUnauthorized(fmt.Sprintf("unable to find account: %s", msg.Signer))
	}

	c, err := h.mgr.Keeper().GetMimir(ctx, constants.NativeTransactionFee.String())
	if err != nil || c < 0 {
		c = h.mgr.GetConstants().GetInt64Value(constants.NativeTransactionFee)
	}
	cost := cosmos.NewUint(uint64(c))
	if cost.GT(nodeAccount.Bond) {
		cost = nodeAccount.Bond
	}

	// set the cryptonote data on the vault
	iter := h.mgr.Keeper().GetVaultIterator(ctx)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		// get the vault
		var vault Vault
		if err := h.mgr.Keeper().Cdc().UnmarshalBinaryBare(iter.Value(), &vault); err != nil {
			ctx.Logger().Error("fail to unmarshal vault", "error", err)
			return fmt.Errorf("fail to unmarshal vault: %w", err)
		}

		// check if it belongs to this node
		if vault.PubKey.String() == nodeAccount.PubKeySet.Secp256k1.String() {
			// set the cryptonote data for this vault
			vault.CryptonoteData = msg.CryptonoteData
			err = h.mgr.Keeper().SetVault(ctx, vault)
			if err != nil {
				return fmt.Errorf("fail to set vault: %w", err)
			}
			break
		}
	}

	nodeAccount.Bond = common.SafeSub(nodeAccount.Bond, cost) // take bond
	if err := h.mgr.Keeper().SetNodeAccount(ctx, nodeAccount); err != nil {
		return fmt.Errorf("fail to save node account: %w", err)
	}

	// add cost to reserve
	coin := common.NewCoin(common.RuneNative, cost)
	if !cost.IsZero() {
		if err := h.mgr.Keeper().SendFromAccountToModule(ctx, msg.Signer, ReserveName, common.NewCoins(coin)); err != nil {
			ctx.Logger().Error("fail to transfer funds from bond to reserve", "error", err)
			return err
		}
	}

	tx := common.Tx{}
	tx.ID = common.BlankTxID
	tx.FromAddress = nodeAccount.BondAddress
	bondEvent := NewEventBond(cost, BondCost, tx)
	if err := h.mgr.EventMgr().EmitEvent(ctx, bondEvent); err != nil {
		return fmt.Errorf("fail to emit bond event: %w", err)
	}

	ctx.EventManager().EmitEvent(
		cosmos.NewEvent("set_cryptonote_data",
			cosmos.NewAttribute("thor_address", msg.Signer.String()),
			cosmos.NewAttribute("cryptonote_data", msg.CryptonoteData)))

	return nil
}
