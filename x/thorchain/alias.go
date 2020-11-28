package thorchain

import (
	mem "gitlab.com/thorchain/thornode/x/thorchain/memo"
	"gitlab.com/thorchain/thornode/x/thorchain/types"
)

const (
	ModuleName       = types.ModuleName
	ReserveName      = types.ReserveName
	AsgardName       = types.AsgardName
	BondName         = types.BondName
	RouterKey        = types.RouterKey
	StoreKey         = types.StoreKey
	DefaultCodespace = types.DefaultCodespace

	// pool status
	PoolAvailable = types.Available
	PoolStaged    = types.Staged
	PoolSuspended = types.Suspended

	// Admin config keys
	MaxWithdrawBasisPoints = types.MaxWithdrawBasisPoints

	// Vaults
	AsgardVault    = types.AsgardVault
	YggdrasilVault = types.YggdrasilVault
	ActiveVault    = types.ActiveVault
	InactiveVault  = types.InactiveVault
	RetiringVault  = types.RetiringVault

	// Node status
	NodeActive      = types.Active
	NodeWhiteListed = types.WhiteListed
	NodeDisabled    = types.Disabled
	NodeReady       = types.Ready
	NodeStandby     = types.Standby
	NodeUnknown     = types.Unknown

	// Bond type
	BondPaid     = types.BondPaid
	BondReturned = types.BondReturned
	AsgardKeygen = types.AsgardKeygen

	// Memos
	TxSwap            = mem.TxSwap
	TxAdd             = mem.TxAdd
	TxBond            = mem.TxBond
	TxYggdrasilFund   = mem.TxYggdrasilFund
	TxYggdrasilReturn = mem.TxYggdrasilReturn
	TxMigrate         = mem.TxMigrate
	TxRagnarok        = mem.TxRagnarok
	TxReserve         = mem.TxReserve
)

var (
	NewPool                        = types.NewPool
	NewTxMarker                    = types.NewTxMarker
	NewNetwork                     = types.NewNetwork
	NewObservedTx                  = types.NewObservedTx
	NewTssVoter                    = types.NewTssVoter
	NewBanVoter                    = types.NewBanVoter
	NewErrataTxVoter               = types.NewErrataTxVoter
	NewObservedTxVoter             = types.NewObservedTxVoter
	NewMsgMimir                    = types.NewMsgMimir
	NewMsgNativeTx                 = types.NewMsgNativeTx
	NewMsgTssPool                  = types.NewMsgTssPool
	NewMsgTssKeysignFail           = types.NewMsgTssKeysignFail
	NewMsgObservedTxIn             = types.NewMsgObservedTxIn
	NewMsgObservedTxOut            = types.NewMsgObservedTxOut
	NewMsgNoOp                     = types.NewMsgNoOp
	NewMsgDonate                   = types.NewMsgDonate
	NewMsgAddLiquidity             = types.NewMsgAddLiquidity
	NewMsgWithdrawLiquidity        = types.NewMsgWithdrawLiquidity
	NewMsgSwap                     = types.NewMsgSwap
	NewKeygen                      = types.NewKeygen
	NewKeygenBlock                 = types.NewKeygenBlock
	NewMsgSetNodeKeys              = types.NewMsgSetNodeKeys
	NewTxOut                       = types.NewTxOut
	NewEventRewards                = types.NewEventRewards
	NewEventPool                   = types.NewEventPool
	NewEventDonate                 = types.NewEventDonate
	NewEventSwap                   = types.NewEventSwap
	NewEventAddLiquidity           = types.NewEventAddLiquidity
	NewEventWithdraw               = types.NewEventWithdraw
	NewEventRefund                 = types.NewEventRefund
	NewEventBond                   = types.NewEventBond
	NewEventGas                    = types.NewEventGas
	NewEventSlash                  = types.NewEventSlash
	NewEventSlashPoint             = types.NewEventSlashPoint
	NewEventReserve                = types.NewEventReserve
	NewEventErrata                 = types.NewEventErrata
	NewEventFee                    = types.NewEventFee
	NewEventOutbound               = types.NewEventOutbound
	NewEventTssKeygenMetric        = types.NewEventTssKeygenMetric
	NewEventTssKeysignMetric       = types.NewEventTssKeysignMetric
	NewPoolMod                     = types.NewPoolMod
	NewMsgRefundTx                 = types.NewMsgRefundTx
	NewMsgOutboundTx               = types.NewMsgOutboundTx
	NewMsgMigrate                  = types.NewMsgMigrate
	NewMsgRagnarok                 = types.NewMsgRagnarok
	NewQueryNodeAccount            = types.NewQueryNodeAccount
	GetThreshold                   = types.GetThreshold
	ModuleCdc                      = types.ModuleCdc
	RegisterCodec                  = types.RegisterCodec
	NewNodeAccount                 = types.NewNodeAccount
	NewVault                       = types.NewVault
	NewReserveContributor          = types.NewReserveContributor
	NewMsgYggdrasil                = types.NewMsgYggdrasil
	NewMsgReserveContributor       = types.NewMsgReserveContributor
	NewMsgBond                     = types.NewMsgBond
	NewMsgUnBond                   = types.NewMsgUnBond
	NewMsgErrataTx                 = types.NewMsgErrataTx
	NewMsgBan                      = types.NewMsgBan
	NewMsgSwitch                   = types.NewMsgSwitch
	NewMsgLeave                    = types.NewMsgLeave
	NewMsgSetVersion               = types.NewMsgSetVersion
	NewMsgSetIPAddress             = types.NewMsgSetIPAddress
	NewMsgNetworkFee               = types.NewMsgNetworkFee
	NewNetworkFee                  = types.NewNetworkFee
	GetPoolStatus                  = types.GetPoolStatus
	GetRandomVault                 = types.GetRandomVault
	GetRandomTx                    = types.GetRandomTx
	GetRandomObservedTx            = types.GetRandomObservedTx
	GetRandomNodeAccount           = types.GetRandomNodeAccount
	GetRandomTHORAddress           = types.GetRandomTHORAddress
	GetRandomRUNEAddress           = types.GetRandomRUNEAddress
	GetRandomBNBAddress            = types.GetRandomBNBAddress
	GetRandomBTCAddress            = types.GetRandomBTCAddress
	GetRandomTxHash                = types.GetRandomTxHash
	GetRandomBech32Addr            = types.GetRandomBech32Addr
	GetRandomBech32ConsensusPubKey = types.GetRandomBech32ConsensusPubKey
	GetRandomPubKey                = types.GetRandomPubKey
	GetRandomPubKeySet             = types.GetRandomPubKeySet
	SetupConfigForTest             = types.SetupConfigForTest
	HasSimpleMajority              = types.HasSimpleMajority
	NewTssKeysignMetric            = types.NewTssKeysignMetric

	// Memo
	ParseMemo          = mem.ParseMemo
	NewRefundMemo      = mem.NewRefundMemo
	NewOutboundMemo    = mem.NewOutboundMemo
	NewRagnarokMemo    = mem.NewRagnarokMemo
	NewYggdrasilReturn = mem.NewYggdrasilReturn
	NewYggdrasilFund   = mem.NewYggdrasilFund
	NewMigrateMemo     = mem.NewMigrateMemo
)

type (
	MsgSend                        = types.MsgSend
	MsgNativeTx                    = types.MsgNativeTx
	MsgSwitch                      = types.MsgSwitch
	MsgBond                        = types.MsgBond
	MsgUnBond                      = types.MsgUnBond
	MsgNoOp                        = types.MsgNoOp
	MsgDonate                      = types.MsgDonate
	MsgWithdrawLiquidity           = types.MsgWithdrawLiquidity
	MsgAddLiquidity                = types.MsgAddLiquidity
	MsgOutboundTx                  = types.MsgOutboundTx
	MsgMimir                       = types.MsgMimir
	MsgMigrate                     = types.MsgMigrate
	MsgRagnarok                    = types.MsgRagnarok
	MsgRefundTx                    = types.MsgRefundTx
	MsgErrataTx                    = types.MsgErrataTx
	MsgBan                         = types.MsgBan
	MsgSwap                        = types.MsgSwap
	MsgSetVersion                  = types.MsgSetVersion
	MsgSetIPAddress                = types.MsgSetIPAddress
	MsgSetNodeKeys                 = types.MsgSetNodeKeys
	MsgLeave                       = types.MsgLeave
	MsgReserveContributor          = types.MsgReserveContributor
	MsgYggdrasil                   = types.MsgYggdrasil
	MsgObservedTxIn                = types.MsgObservedTxIn
	MsgObservedTxOut               = types.MsgObservedTxOut
	MsgTssPool                     = types.MsgTssPool
	MsgTssKeysignFail              = types.MsgTssKeysignFail
	MsgNetworkFee                  = types.MsgNetworkFee
	QueryVersion                   = types.QueryVersion
	QueryQueue                     = types.QueryQueue
	QueryNodeAccountPreflightCheck = types.QueryNodeAccountPreflightCheck
	QueryKeygenBlock               = types.QueryKeygenBlock
	QueryResLastBlockHeights       = types.QueryResLastBlockHeights
	QueryKeysign                   = types.QueryKeysign
	QueryYggdrasilVaults           = types.QueryYggdrasilVaults
	QueryNodeAccount               = types.QueryNodeAccount
	QueryChainAddress              = types.QueryChainAddress
	PoolStatus                     = types.PoolStatus
	Pool                           = types.Pool
	Pools                          = types.Pools
	LiquidityProvider              = types.LiquidityProvider
	LiquidityProviders             = types.LiquidityProviders
	ObservedTxs                    = types.ObservedTxs
	ObservedTx                     = types.ObservedTx
	ObservedTxVoter                = types.ObservedTxVoter
	ObservedTxVoters               = types.ObservedTxVoters
	BanVoter                       = types.BanVoter
	ErrataTxVoter                  = types.ErrataTxVoter
	TssVoter                       = types.TssVoter
	TssKeysignFailVoter            = types.TssKeysignFailVoter
	TxOutItem                      = types.TxOutItem
	TxOut                          = types.TxOut
	Keygen                         = types.Keygen
	KeygenBlock                    = types.KeygenBlock
	EventSwap                      = types.EventSwap
	EventAddLiquidity              = types.EventAddLiquidity
	EventWithdraw                  = types.EventWithdraw
	EventDonate                    = types.EventDonate
	EventRewards                   = types.EventRewards
	EventErrata                    = types.EventErrata
	EventReserve                   = types.EventReserve
	PoolAmt                        = types.PoolAmt
	PoolMod                        = types.PoolMod
	PoolMods                       = types.PoolMods
	ReserveContributor             = types.ReserveContributor
	ReserveContributors            = types.ReserveContributors
	Vault                          = types.Vault
	Vaults                         = types.Vaults
	NodeAccount                    = types.NodeAccount
	NodeAccounts                   = types.NodeAccounts
	NodeStatus                     = types.NodeStatus
	Network                        = types.Network
	VaultStatus                    = types.VaultStatus
	GasPool                        = types.GasPool
	EventGas                       = types.EventGas
	TxMarker                       = types.TxMarker
	TxMarkers                      = types.TxMarkers
	EventPool                      = types.EventPool
	EventRefund                    = types.EventRefund
	EventBond                      = types.EventBond
	EventFee                       = types.EventFee
	EventSlash                     = types.EventSlash
	EventOutbound                  = types.EventOutbound
	NetworkFee                     = types.NetworkFee
	ObservedNetworkFeeVoter        = types.ObservedNetworkFeeVoter
	Jail                           = types.Jail
	RagnarokWithdrawPosition       = types.RagnarokWithdrawPosition

	// Memo
	SwapMemo              = mem.SwapMemo
	AddLiquidityMemo      = mem.AddLiquidityMemo
	WithdrawLiquidityMemo = mem.WithdrawLiquidityMemo
	DonateMemo            = mem.DonateMemo
	RefundMemo            = mem.RefundMemo
	MigrateMemo           = mem.MigrateMemo
	RagnarokMemo          = mem.RagnarokMemo
	BondMemo              = mem.BondMemo
	UnbondMemo            = mem.UnbondMemo
	OutboundMemo          = mem.OutboundMemo
	LeaveMemo             = mem.LeaveMemo
	YggdrasilFundMemo     = mem.YggdrasilFundMemo
	YggdrasilReturnMemo   = mem.YggdrasilReturnMemo
	ReserveMemo           = mem.ReserveMemo
	SwitchMemo            = mem.SwitchMemo
)
