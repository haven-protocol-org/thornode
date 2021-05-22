package thorchain

import (
	"fmt"

	"github.com/blang/semver"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	"gitlab.com/thorchain/thornode/x/thorchain/keeper"
)

// IPAddressHandler is to handle ip address message
type CryptonoteDataHandler struct {
	keeper keeper.Keeper
	mgr    Manager
}

// NewCryptonoteDataHandler create new instance of IPAddressHandler
func NewCryptonoteDataHandler(keeper keeper.Keeper, mgr Manager) CryptonoteDataHandler {
	return CryptonoteDataHandler{
		keeper: keeper,
		mgr:    mgr,
	}
}

// Run it the main entry point to execute cn data logic
func (h CryptonoteDataHandler) Run(ctx cosmos.Context, m cosmos.Msg, version semver.Version, constAccessor constants.ConstantValues) (*cosmos.Result, error) {
	msg, ok := m.(*MsgSetCryptonoteData)
	if !ok {
		return nil, errInvalidMessage
	}
	ctx.Logger().Info("receive cryotonote data", "data", msg.CryptonoteData)
	if err := h.validate(ctx, *msg, version, constAccessor); err != nil {
		ctx.Logger().Error("msg set version failed validation", "error", err)
		return nil, err
	}
	if err := h.handle(ctx, *msg, version, constAccessor); err != nil {
		ctx.Logger().Error("fail to process msg set version", "error", err)
		return nil, err
	}

	return &cosmos.Result{}, nil
}

func (h CryptonoteDataHandler) validate(ctx cosmos.Context, msg MsgSetCryptonoteData, version semver.Version, constAccessor constants.ConstantValues) error {
	if version.GTE(semver.MustParse("0.1.0")) {
		return h.validateV1(ctx, msg, constAccessor)
	}
	return errBadVersion
}

func (h CryptonoteDataHandler) validateV1(ctx cosmos.Context, msg MsgSetCryptonoteData, constAccessor constants.ConstantValues) error {
	if err := msg.ValidateBasic(); err != nil {
		return err
	}

	nodeAccount, err := h.keeper.GetNodeAccount(ctx, msg.Signer)
	if err != nil {
		ctx.Logger().Error("fail to get node account", "error", err, "address", msg.Signer.String())
		return cosmos.ErrUnauthorized(fmt.Sprintf("%s is not authorizaed", msg.Signer))
	}
	if nodeAccount.IsEmpty() {
		ctx.Logger().Error("unauthorized account", "address", msg.Signer.String())
		return cosmos.ErrUnauthorized(fmt.Sprintf("%s is not authorizaed", msg.Signer))
	}

	cost := constAccessor.GetInt64Value(constants.CliTxCost)
	if nodeAccount.Bond.LT(cosmos.NewUint(uint64(cost))) {
		return cosmos.ErrUnauthorized("not enough bond")
	}

	return nil
}

func (h CryptonoteDataHandler) handle(ctx cosmos.Context, msg MsgSetCryptonoteData, version semver.Version, constAccessor constants.ConstantValues) error {
	ctx.Logger().Info("handleMsgSetCryptonoteData request", "cryotonote data", msg.CryptonoteData)
	if version.GTE(semver.MustParse("0.1.0")) {
		return h.handleV1(ctx, msg, constAccessor)
	}
	ctx.Logger().Error(errInvalidVersion.Error())
	return errBadVersion
}

func (h CryptonoteDataHandler) handleV1(ctx cosmos.Context, msg MsgSetCryptonoteData, constAccessor constants.ConstantValues) error {
	nodeAccount, err := h.keeper.GetNodeAccount(ctx, msg.Signer)
	if err != nil {
		ctx.Logger().Error("fail to get node account", "error", err, "address", msg.Signer.String())
		return cosmos.ErrUnauthorized(fmt.Sprintf("unable to find account: %s", msg.Signer))
	}

	cost := cosmos.NewUint(uint64(constAccessor.GetInt64Value(constants.CliTxCost)))
	if cost.GT(nodeAccount.Bond) {
		cost = nodeAccount.Bond
	}

	// set the cryptonote data on the vault
	iter := h.keeper.GetVaultIterator(ctx)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		// get the vault
		var vault Vault
		if err := h.keeper.Cdc().UnmarshalBinaryBare(iter.Value(), &vault); err != nil {
			ctx.Logger().Error("fail to unmarshal vault", "error", err)
			return fmt.Errorf("fail to unmarshal vault: %w", err)
		}

		// check if it belongs to this node
		if vault.PubKey.String() == nodeAccount.PubKeySet.Secp256k1.String() {
			// set the cryptonote data for this vault
			vault.CryptonoteData = msg.CryptonoteData
			err = h.keeper.SetVault(ctx, vault)
			if err != nil {
				return fmt.Errorf("fail to set vault: %w", err)
			}
			break
		}
	}

	nodeAccount.Bond = common.SafeSub(nodeAccount.Bond, cost) // take bond
	if err := h.keeper.SetNodeAccount(ctx, nodeAccount); err != nil {
		return fmt.Errorf("fail to save node account: %w", err)
	}

	// add cost to reserve
	coin := common.NewCoin(common.RuneNative, cost)
	if !cost.IsZero() {
		if err := h.keeper.SendFromAccountToModule(ctx, msg.Signer, ReserveName, common.NewCoins(coin)); err != nil {
			ctx.Logger().Error("fail to transfer funds from bond to reserve", "error", err)
			return err
		}
	}

	ctx.EventManager().EmitEvent(
		cosmos.NewEvent("set_cryptonote_data",
			cosmos.NewAttribute("thor_address", msg.Signer.String()),
			cosmos.NewAttribute("cryptonote_data", msg.CryptonoteData)))

	return nil
}
