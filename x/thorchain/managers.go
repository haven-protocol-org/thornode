package thorchain

import (
	"errors"
	"fmt"

	"github.com/blang/semver"
	"github.com/cosmos/cosmos-sdk/codec"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	"gitlab.com/thorchain/thornode/x/thorchain/keeper"
	kv1 "gitlab.com/thorchain/thornode/x/thorchain/keeper/v1"
)

const (
	genesisBlockHeight = 1
)

// ErrNotEnoughToPayFee will happen when the emitted asset is not enough to pay for fee
var ErrNotEnoughToPayFee = errors.New("not enough asset to pay for fees")

// Manager is an interface to define all the required methods
type Manager interface {
	Keeper() keeper.Keeper
	GasMgr() GasManager
	EventMgr() EventManager
	TxOutStore() TxOutStore
	VaultMgr() NetworkManager
	ValidatorMgr() ValidatorManager
	ObMgr() ObserverManager
	SwapQ() SwapQueue
	Slasher() Slasher
	YggManager() YggManager
}

// GasManager define all the methods required to manage gas
type GasManager interface {
	BeginBlock()
	EndBlock(ctx cosmos.Context, keeper keeper.Keeper, eventManager EventManager)
	AddGasAsset(gas common.Gas, increaseTxCount bool)
	ProcessGas(ctx cosmos.Context, keeper keeper.Keeper)
	GetGas() common.Gas
	GetFee(ctx cosmos.Context, chain common.Chain, asset common.Asset) cosmos.Uint
	GetMaxGas(ctx cosmos.Context, chain common.Chain) (common.Coin, error)
	GetGasRate(ctx cosmos.Context, chain common.Chain) cosmos.Uint
	SubGas(gas common.Gas)
}

// EventManager define methods need to be support to manage events
type EventManager interface {
	EmitEvent(ctx cosmos.Context, evt EmitEventItem) error
	EmitGasEvent(ctx cosmos.Context, gasEvent *EventGas) error
	EmitSwapEvent(ctx cosmos.Context, swap *EventSwap) error
	EmitFeeEvent(ctx cosmos.Context, feeEvent *EventFee) error
}

// TxOutStore define the method required for TxOutStore
type TxOutStore interface {
	GetBlockOut(ctx cosmos.Context) (*TxOut, error)
	ClearOutboundItems(ctx cosmos.Context)
	GetOutboundItems(ctx cosmos.Context) ([]TxOutItem, error)
	TryAddTxOutItem(ctx cosmos.Context, mgr Manager, toi TxOutItem) (bool, error)
	UnSafeAddTxOutItem(ctx cosmos.Context, mgr Manager, toi TxOutItem) error
	GetOutboundItemByToAddress(_ cosmos.Context, _ common.Address) []TxOutItem
}

// ObserverManager define the method to manage observes
type ObserverManager interface {
	BeginBlock()
	EndBlock(ctx cosmos.Context, keeper keeper.Keeper)
	AppendObserver(chain common.Chain, addrs []cosmos.AccAddress)
	List() []cosmos.AccAddress
}

// ValidatorManager define the method to manage validators
type ValidatorManager interface {
	BeginBlock(ctx cosmos.Context, constAccessor constants.ConstantValues, existingValidators []string) error
	EndBlock(ctx cosmos.Context, mgr Manager, constAccessor constants.ConstantValues) []abci.ValidatorUpdate
	RequestYggReturn(ctx cosmos.Context, node NodeAccount, mgr Manager, constAccessor constants.ConstantValues) error
	processRagnarok(ctx cosmos.Context, mgr Manager, constAccessor constants.ConstantValues) error
	NodeAccountPreflightCheck(ctx cosmos.Context, na NodeAccount, constAccessor constants.ConstantValues) (NodeStatus, error)
}

// NetworkManager interface define the contract of Vault Manager
type NetworkManager interface {
	TriggerKeygen(ctx cosmos.Context, nas NodeAccounts) error
	RotateVault(ctx cosmos.Context, vault Vault) error
	EndBlock(ctx cosmos.Context, mgr Manager, constAccessor constants.ConstantValues) error
	UpdateNetwork(ctx cosmos.Context, constAccessor constants.ConstantValues, gasManager GasManager, eventMgr EventManager) error
	RecallChainFunds(ctx cosmos.Context, chain common.Chain, mgr Manager, excludeNode common.PubKeys) error
}

// SwapQueue interface define the contract of Swap Queue
type SwapQueue interface {
	EndBlock(ctx cosmos.Context, mgr Manager, version semver.Version, constAccessor constants.ConstantValues) error
}

// Slasher define all the method to perform slash
type Slasher interface {
	BeginBlock(ctx cosmos.Context, req abci.RequestBeginBlock, constAccessor constants.ConstantValues)
	HandleDoubleSign(ctx cosmos.Context, addr crypto.Address, infractionHeight int64, constAccessor constants.ConstantValues) error
	LackObserving(ctx cosmos.Context, constAccessor constants.ConstantValues) error
	LackSigning(ctx cosmos.Context, constAccessor constants.ConstantValues, mgr Manager) error
	SlashVault(ctx cosmos.Context, vaultPK common.PubKey, coins common.Coins, mgr Manager) error
	IncSlashPoints(ctx cosmos.Context, point int64, addresses ...cosmos.AccAddress)
	DecSlashPoints(ctx cosmos.Context, point int64, addresses ...cosmos.AccAddress)
}

// YggManager define method to fund yggdrasil
type YggManager interface {
	Fund(ctx cosmos.Context, mgr Manager, constAccessor constants.ConstantValues) error
}

// Mgrs is an implementation of Manager interface
type Mgrs struct {
	CurrentVersion semver.Version
	gasMgr         GasManager
	eventMgr       EventManager
	txOutStore     TxOutStore
	networkMgr     NetworkManager
	validatorMgr   ValidatorManager
	obMgr          ObserverManager
	swapQ          SwapQueue
	slasher        Slasher
	yggManager     YggManager

	K             keeper.Keeper
	cdc           codec.BinaryMarshaler
	coinKeeper    bankkeeper.Keeper
	accountKeeper authkeeper.AccountKeeper
	storeKey      cosmos.StoreKey
}

// NewManagers  create a new Manager
func NewManagers(keeper keeper.Keeper, cdc codec.BinaryMarshaler, coinKeeper bankkeeper.Keeper, accountKeeper authkeeper.AccountKeeper, storeKey cosmos.StoreKey) *Mgrs {
	return &Mgrs{
		K:             keeper,
		cdc:           cdc,
		coinKeeper:    coinKeeper,
		accountKeeper: accountKeeper,
		storeKey:      storeKey,
	}
}

// BeginBlock detect whether there are new version available, if it is available then create a new version of Mgr
func (mgr *Mgrs) BeginBlock(ctx cosmos.Context) error {
	v := mgr.K.GetLowestActiveVersion(ctx)
	if v.Equals(mgr.CurrentVersion) {
		return nil
	}
	// version is different , thus all the manager need to re-create
	mgr.CurrentVersion = v
	var err error

	mgr.K, err = GetKeeper(v, mgr.cdc, mgr.coinKeeper, mgr.accountKeeper, mgr.storeKey)
	if err != nil {
		return fmt.Errorf("fail to create keeper: %w", err)
	}
	mgr.gasMgr, err = GetGasManager(v, mgr.K)
	if err != nil {
		return fmt.Errorf("fail to create gas manager: %w", err)
	}
	mgr.eventMgr, err = GetEventManager(v)
	if err != nil {
		return fmt.Errorf("fail to get event manager: %w", err)
	}
	mgr.txOutStore, err = GetTxOutStore(mgr.K, v, mgr.eventMgr, mgr.gasMgr)
	if err != nil {
		return fmt.Errorf("fail to get tx out store: %w", err)
	}

	mgr.networkMgr, err = GetVaultManager(mgr.K, v, mgr.txOutStore, mgr.eventMgr)
	if err != nil {
		return fmt.Errorf("fail to get vault manager: %w", err)
	}

	mgr.validatorMgr, err = GetValidatorManager(mgr.K, v, mgr.networkMgr, mgr.txOutStore, mgr.eventMgr)
	if err != nil {
		return fmt.Errorf("fail to get validator manager: %w", err)
	}

	mgr.obMgr, err = GetObserverManager(v)
	if err != nil {
		return fmt.Errorf("fail to get observer manager: %w", err)
	}

	mgr.swapQ, err = GetSwapQueue(mgr.K, v)
	if err != nil {
		return fmt.Errorf("fail to create swap queue: %w", err)
	}

	mgr.slasher, err = GetSlasher(mgr.K, v, mgr.eventMgr)
	if err != nil {
		return fmt.Errorf("fail to create swap queue: %w", err)
	}

	mgr.yggManager, err = GetYggManager(mgr.K, v)
	if err != nil {
		return fmt.Errorf("fail to create swap queue: %w", err)
	}
	return nil
}

// Keeper return Keeper
func (mgr *Mgrs) Keeper() keeper.Keeper { return mgr.K }

// GasMgr return GasManager
func (mgr *Mgrs) GasMgr() GasManager { return mgr.gasMgr }

// EventMgr return EventMgr
func (mgr *Mgrs) EventMgr() EventManager { return mgr.eventMgr }

// TxOutStore return an TxOutStore
func (mgr *Mgrs) TxOutStore() TxOutStore { return mgr.txOutStore }

// VaultMgr return a valid NetworkManager
func (mgr *Mgrs) VaultMgr() NetworkManager { return mgr.networkMgr }

// ValidatorMgr return an implementation of ValidatorManager
func (mgr *Mgrs) ValidatorMgr() ValidatorManager { return mgr.validatorMgr }

// ObMgr return an implementation of ObserverManager
func (mgr *Mgrs) ObMgr() ObserverManager { return mgr.obMgr }

// SwapQ return an implementation of SwapQueue
func (mgr *Mgrs) SwapQ() SwapQueue { return mgr.swapQ }

// Slasher return an implementation of Slasher
func (mgr *Mgrs) Slasher() Slasher { return mgr.slasher }

// YggManager return an implementation of YggManager
func (mgr *Mgrs) YggManager() YggManager { return mgr.yggManager }

// GetKeeper return Keeper
func GetKeeper(version semver.Version, cdc codec.BinaryMarshaler, coinKeeper bankkeeper.Keeper, accountKeeper authkeeper.AccountKeeper, storeKey cosmos.StoreKey) (keeper.Keeper, error) {
	if version.GTE(semver.MustParse("0.1.0")) {
		return kv1.NewKVStore(cdc, coinKeeper, accountKeeper, storeKey), nil
	}
	return nil, errInvalidVersion
}

// GetGasManager return GasManager
func GetGasManager(version semver.Version, keeper keeper.Keeper) (GasManager, error) {
	constAcessor := constants.GetConstantValues(version)
	if version.GTE(semver.MustParse("0.1.0")) {
		return NewGasMgrV1(constAcessor, keeper), nil
	}
	return nil, errInvalidVersion
}

// GetEventManager will return an implementation of EventManager
func GetEventManager(version semver.Version) (EventManager, error) {
	if version.GTE(semver.MustParse("0.1.0")) {
		return NewEventMgrV1(), nil
	}
	return nil, errInvalidVersion
}

// GetTxOutStore will return an implementation of the txout store that
func GetTxOutStore(keeper keeper.Keeper, version semver.Version, eventMgr EventManager, gasManager GasManager) (TxOutStore, error) {
	constAcessor := constants.GetConstantValues(version)
	if version.GTE(semver.MustParse("0.54.0")) {
		return NewTxOutStorageV54(keeper, constAcessor, eventMgr, gasManager), nil
	} else if version.GTE(semver.MustParse("0.53.0")) {
		return NewTxOutStorageV53(keeper, constAcessor, eventMgr, gasManager), nil
	} else if version.GTE(semver.MustParse("0.52.0")) {
		return NewTxOutStorageV52(keeper, constAcessor, eventMgr, gasManager), nil
	} else if version.GTE(semver.MustParse("0.51.0")) {
		return NewTxOutStorageV51(keeper, constAcessor, eventMgr, gasManager), nil
	} else if version.GTE(semver.MustParse("0.46.0")) {
		return NewTxOutStorageV46(keeper, constAcessor, eventMgr, gasManager), nil
	} else if version.GTE(semver.MustParse("0.1.0")) {
		return NewTxOutStorageV1(keeper, constAcessor, eventMgr, gasManager), nil
	}
	return nil, errInvalidVersion
}

// GetVaultManager retrieve a NetworkManager that is compatible with the given version
func GetVaultManager(keeper keeper.Keeper, version semver.Version, txOutStore TxOutStore, eventMgr EventManager) (NetworkManager, error) {
	if version.GTE(semver.MustParse("0.1.0")) {
		return NewNetworkMgrV1(keeper, txOutStore, eventMgr), nil
	}
	return nil, errInvalidVersion
}

// GetValidatorManager create a new instance of Validator Manager
func GetValidatorManager(keeper keeper.Keeper, version semver.Version, vaultMgr NetworkManager, txOutStore TxOutStore, eventMgr EventManager) (ValidatorManager, error) {
	if version.GTE(semver.MustParse("0.51.0")) {
		return newValidatorMgrV51(keeper, vaultMgr, txOutStore, eventMgr), nil
	} else if version.GTE(semver.MustParse("0.1.0")) {
		return newValidatorMgrV1(keeper, vaultMgr, txOutStore, eventMgr), nil
	}
	return nil, errInvalidVersion
}

// GetObserverManager return an instance that implements ObserverManager interface
// when there is no version can match the given semver , it will return nil
func GetObserverManager(version semver.Version) (ObserverManager, error) {
	if version.GTE(semver.MustParse("0.1.0")) {
		return NewObserverMgrV1(), nil
	}
	return nil, errInvalidVersion
}

// GetSwapQueue retrieve a SwapQueue that is compatible with the given version
func GetSwapQueue(keeper keeper.Keeper, version semver.Version) (SwapQueue, error) {
	if version.GTE(semver.MustParse("0.47.0")) {
		return NewSwapQv47(keeper), nil
	} else if version.GTE(semver.MustParse("0.1.0")) {
		return NewSwapQv1(keeper), nil
	}
	return nil, errInvalidVersion
}

// GetSlasher return an implementation of Slasher
func GetSlasher(keeper keeper.Keeper, version semver.Version, eventMgr EventManager) (Slasher, error) {
	if version.GTE(semver.MustParse("0.54.0")) {
		return NewSlasherV54(keeper, eventMgr), nil
	} else if version.GTE(semver.MustParse("0.48.0")) {
		return NewSlasherV48(keeper, eventMgr), nil
	} else if version.GTE(semver.MustParse("0.47.0")) {
		return NewSlasherV47(keeper, eventMgr), nil
	} else if version.GTE(semver.MustParse("0.44.0")) {
		return NewSlasherV44(keeper, eventMgr), nil
	} else if version.GTE(semver.MustParse("0.43.0")) {
		return NewSlasherV43(keeper, eventMgr), nil
	} else if version.GTE(semver.MustParse("0.1.0")) {
		return NewSlasherV1(keeper, eventMgr), nil
	}
	return nil, errInvalidVersion
}

// GetYggManager return an implementation of YggManager
func GetYggManager(keeper keeper.Keeper, version semver.Version) (YggManager, error) {
	if version.GTE(semver.MustParse("0.45.0")) {
		return NewYggMgrV45(keeper), nil
	} else if version.GTE(semver.MustParse("0.1.0")) {
		return NewYggMgrV1(keeper), nil
	}
	return nil, errInvalidVersion
}
