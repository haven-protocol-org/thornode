package types

import (
	"fmt"
	"strconv"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
)

// all event types support by THORChain
const (
	SwapEventType             = `swap`
	AddLiquidityEventType     = `add_liquidity`
	WithdrawEventType         = `withdraw`
	DonateEventType           = `donate`
	PoolEventType             = `pool`
	RewardEventType           = `rewards`
	RefundEventType           = `refund`
	BondEventType             = `bond`
	GasEventType              = `gas`
	ReserveEventType          = `reserve`
	SlashEventType            = `slash`
	ErrataEventType           = `errata`
	FeeEventType              = `fee`
	OutboundEventType         = `outbound`
	TSSKeygenMetricEventType  = `tss_keygen`
	TSSKeysignMetricEventType = `tss_keysign`
	SlashPointEventType       = `slash_points`
)

// PoolMods a list of pool modifications
type PoolMods []PoolMod

// NewPoolMod create a new instance of PoolMod
func NewPoolMod(asset common.Asset, runeAmt cosmos.Uint, runeAdd bool, assetAmt cosmos.Uint, assetAdd bool) PoolMod {
	return PoolMod{
		Asset:    asset,
		RuneAmt:  runeAmt,
		RuneAdd:  runeAdd,
		AssetAmt: assetAmt,
		AssetAdd: assetAdd,
	}
}

// NewEventSwap create a new swap event
func NewEventSwap(pool common.Asset, priceTarget, fee, tradeSlip, liquidityFeeInRune cosmos.Uint, inTx common.Tx, emitAsset common.Coin) *EventSwap {
	return &EventSwap{
		Pool:               pool,
		PriceTarget:        priceTarget,
		TradeSlip:          tradeSlip,
		LiquidityFee:       fee,
		LiquidityFeeInRune: liquidityFeeInRune,
		InTx:               inTx,
		EmitAsset:          emitAsset,
	}
}

// Type return a string that represent the type, it should not duplicated with other event
func (m *EventSwap) Type() string {
	return SwapEventType
}

// Events convert EventSwap to key value pairs used in cosmos
func (m *EventSwap) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("pool", m.Pool.String()),
		cosmos.NewAttribute("price_target", m.PriceTarget.String()),
		cosmos.NewAttribute("trade_slip", m.TradeSlip.String()),
		cosmos.NewAttribute("liquidity_fee", m.LiquidityFee.String()),
		cosmos.NewAttribute("liquidity_fee_in_rune", m.LiquidityFeeInRune.String()),
		cosmos.NewAttribute("emit_asset", m.EmitAsset.String()),
	)
	evt = evt.AppendAttributes(m.InTx.ToAttributes()...)
	return cosmos.Events{evt}, nil
}

// NewEventAddLiquidity create a new add liquidity event
func NewEventAddLiquidity(pool common.Asset,
	su cosmos.Uint,
	runeAddress common.Address,
	runeAmount,
	assetAmount cosmos.Uint,
	runeTxID,
	assetTxID common.TxID,
	assetAddress common.Address) *EventAddLiquidity {
	return &EventAddLiquidity{
		Pool:          pool,
		ProviderUnits: su,
		RuneAddress:   runeAddress,
		RuneAmount:    runeAmount,
		AssetAmount:   assetAmount,
		RuneTxID:      runeTxID,
		AssetTxID:     assetTxID,
		AssetAddress:  assetAddress,
	}
}

// Type return the event type
func (m *EventAddLiquidity) Type() string {
	return AddLiquidityEventType
}

// Events return cosmos.Events which is cosmos.Attribute(key value pairs)
func (m *EventAddLiquidity) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("pool", m.Pool.String()),
		cosmos.NewAttribute("liquidity_provider_units", m.ProviderUnits.String()),
		cosmos.NewAttribute("rune_address", m.RuneAddress.String()),
		cosmos.NewAttribute("rune_amount", m.RuneAmount.String()),
		cosmos.NewAttribute("asset_amount", m.AssetAmount.String()),
		cosmos.NewAttribute("asset_address", m.AssetAddress.String()),
	)
	if !m.RuneTxID.Equals(m.AssetTxID) && !m.RuneTxID.IsEmpty() {
		evt = evt.AppendAttributes(cosmos.NewAttribute(fmt.Sprintf("%s_txid", common.RuneAsset().Chain), m.RuneTxID.String()))
	}

	if !m.AssetTxID.IsEmpty() {
		evt = evt.AppendAttributes(cosmos.NewAttribute(fmt.Sprintf("%s_txid", m.Pool.Chain), m.AssetTxID.String()))
	}
	return cosmos.Events{
		evt,
	}, nil
}

// NewEventWithdraw create a new withdraw event
func NewEventWithdraw(pool common.Asset, su cosmos.Uint, basisPts int64, asym cosmos.Dec, inTx common.Tx, emitAsset, emitRune cosmos.Uint) *EventWithdraw {
	return &EventWithdraw{
		Pool:          pool,
		ProviderUnits: su,
		BasisPoints:   basisPts,
		Asymmetry:     asym,
		InTx:          inTx,
		EmitAsset:     emitAsset,
		EmitRune:      emitRune,
	}
}

// Type return the withdraw event type
func (m *EventWithdraw) Type() string {
	return WithdrawEventType
}

// Events return the cosmos event
func (m *EventWithdraw) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("pool", m.Pool.String()),
		cosmos.NewAttribute("liquidity_provider_units", m.ProviderUnits.String()),
		cosmos.NewAttribute("basis_points", strconv.FormatInt(m.BasisPoints, 10)),
		cosmos.NewAttribute("asymmetry", m.Asymmetry.String()),
		cosmos.NewAttribute("emit_asset", m.EmitAsset.String()),
		cosmos.NewAttribute("emit_rune", m.EmitRune.String()))
	evt = evt.AppendAttributes(m.InTx.ToAttributes()...)
	return cosmos.Events{evt}, nil
}

// NewEventDonate create a new donate event
func NewEventDonate(pool common.Asset, inTx common.Tx) *EventDonate {
	return &EventDonate{
		Pool: pool,
		InTx: inTx,
	}
}

// Type return donate event type
func (m *EventDonate) Type() string {
	return DonateEventType
}

// Events get all events
func (m *EventDonate) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("pool", m.Pool.String()))
	evt = evt.AppendAttributes(m.InTx.ToAttributes()...)
	return cosmos.Events{evt}, nil
}

// NewEventPool create a new pool change event
func NewEventPool(pool common.Asset, status PoolStatus) *EventPool {
	return &EventPool{
		Pool:   pool,
		Status: status,
	}
}

// Type return pool event type
func (m *EventPool) Type() string {
	return PoolEventType
}

// Events provide an instance of cosmos.Events
func (m *EventPool) Events() (cosmos.Events, error) {
	return cosmos.Events{
		cosmos.NewEvent(m.Type(),
			cosmos.NewAttribute("pool", m.Pool.String()),
			cosmos.NewAttribute("pool_status", m.Status.String())),
	}, nil
}

// NewEventRewards create a new reward event
func NewEventRewards(bondReward cosmos.Uint, poolRewards []PoolAmt) *EventRewards {
	return &EventRewards{
		BondReward:  bondReward,
		PoolRewards: poolRewards,
	}
}

// Type return reward event type
func (m *EventRewards) Type() string {
	return RewardEventType
}

// Events return a standard cosmos event
func (m *EventRewards) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("bond_reward", m.BondReward.String()),
	)
	for _, item := range m.PoolRewards {
		evt = evt.AppendAttributes(cosmos.NewAttribute(item.Asset.String(), strconv.FormatInt(item.Amount, 10)))
	}
	return cosmos.Events{evt}, nil
}

// NewEventRefund create a new EventRefund
func NewEventRefund(code uint32, reason string, inTx common.Tx, fee common.Fee) *EventRefund {
	return &EventRefund{
		Code:   code,
		Reason: reason,
		InTx:   inTx,
		Fee:    fee,
	}
}

// Type return reward event type
func (m *EventRefund) Type() string {
	return RefundEventType
}

// Events return events
func (m *EventRefund) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("code", strconv.FormatUint(uint64(m.Code), 10)),
		cosmos.NewAttribute("reason", m.Reason),
	)
	evt = evt.AppendAttributes(m.InTx.ToAttributes()...)
	return cosmos.Events{evt}, nil
}

// NewEventBond create a new Bond Events
func NewEventBond(amount cosmos.Uint, bondType BondType, txIn common.Tx) *EventBond {
	return &EventBond{
		Amount:   amount,
		BondType: bondType,
		TxIn:     txIn,
	}
}

// Type return bond event Type
func (m *EventBond) Type() string {
	return BondEventType
}

// Events return all the event attributes
func (m *EventBond) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("amount", m.Amount.String()),
		cosmos.NewAttribute("bound_type", string(m.BondType)))
	evt = evt.AppendAttributes(m.TxIn.ToAttributes()...)
	return cosmos.Events{evt}, nil
}

// NewEventGas create a new EventGas instance
func NewEventGas() *EventGas {
	return &EventGas{
		Pools: make([]GasPool, 0),
	}
}

// UpsertGasPool update the Gas Pools hold by EventGas instance
// if the given gasPool already exist, then it merge the gasPool with internal one , otherwise add it to the list
func (m *EventGas) UpsertGasPool(pool GasPool) {
	for i, p := range m.Pools {
		if p.Asset == pool.Asset {
			m.Pools[i].RuneAmt = p.RuneAmt.Add(pool.RuneAmt)
			m.Pools[i].AssetAmt = p.AssetAmt.Add(pool.AssetAmt)
			return
		}
	}
	m.Pools = append(m.Pools, pool)
}

// Type return event type
func (m *EventGas) Type() string {
	return GasEventType
}

// Events return a standard cosmos events
func (m *EventGas) Events() (cosmos.Events, error) {
	events := make(cosmos.Events, 0, len(m.Pools))
	for _, item := range m.Pools {
		evt := cosmos.NewEvent(m.Type(),
			cosmos.NewAttribute("asset", item.Asset.String()),
			cosmos.NewAttribute("asset_amt", item.AssetAmt.String()),
			cosmos.NewAttribute("rune_amt", item.RuneAmt.String()),
			cosmos.NewAttribute("transaction_count", strconv.FormatInt(item.Count, 10)))
		events = append(events, evt)
	}
	return events, nil
}

// NewEventReserve create a new instance of EventReserve
func NewEventReserve(contributor ReserveContributor, inTx common.Tx) *EventReserve {
	return &EventReserve{
		ReserveContributor: contributor,
		InTx:               inTx,
	}
}

// Type return the event Type
func (m *EventReserve) Type() string {
	return ReserveEventType
}

// Events return standard cosmos event
func (m *EventReserve) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("contributor_address", m.ReserveContributor.Address.String()),
		cosmos.NewAttribute("amount", m.ReserveContributor.Amount.String()),
	)
	evt = evt.AppendAttributes(m.InTx.ToAttributes()...)
	return cosmos.Events{
		evt,
	}, nil
}

// NewEventSlash create a new slash event
func NewEventSlash(pool common.Asset, slashAmount []PoolAmt) *EventSlash {
	return &EventSlash{
		Pool:        pool,
		SlashAmount: slashAmount,
	}
}

// Type return slash event type
func (m *EventSlash) Type() string {
	return SlashEventType
}

// Events return a standard cosmos events
func (m *EventSlash) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("pool", m.Pool.String()))
	for _, item := range m.SlashAmount {
		evt = evt.AppendAttributes(cosmos.NewAttribute(item.Asset.String(), strconv.FormatInt(item.Amount, 10)))
	}
	return cosmos.Events{evt}, nil
}

// NewEventErrata create a new errata event
func NewEventErrata(txID common.TxID, pools PoolMods) *EventErrata {
	return &EventErrata{
		TxID:  txID,
		Pools: pools,
	}
}

// Type return slash event type
func (m *EventErrata) Type() string {
	return ErrataEventType
}

// Events return a cosmos.Events type
func (m *EventErrata) Events() (cosmos.Events, error) {
	events := make(cosmos.Events, 0, len(m.Pools))
	for _, item := range m.Pools {
		evt := cosmos.NewEvent(m.Type(),
			cosmos.NewAttribute("in_tx_id", m.TxID.String()),
			cosmos.NewAttribute("asset", item.Asset.String()),
			cosmos.NewAttribute("rune_amt", item.RuneAmt.String()),
			cosmos.NewAttribute("rune_add", strconv.FormatBool(item.RuneAdd)),
			cosmos.NewAttribute("asset_amt", item.AssetAmt.String()),
			cosmos.NewAttribute("asset_add", strconv.FormatBool(item.AssetAdd)))
		events = append(events, evt)
	}
	return events, nil
}

// NewEventFee create a new EventFee
func NewEventFee(txID common.TxID, fee common.Fee) *EventFee {
	return &EventFee{
		TxID: txID,
		Fee:  fee,
	}
}

// Type get a string represent the event type
func (m *EventFee) Type() string {
	return FeeEventType
}

// Events return events of cosmos.Event type
func (m *EventFee) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("tx_id", m.TxID.String()),
		cosmos.NewAttribute("coins", m.Fee.Coins.String()),
		cosmos.NewAttribute("pool_deduct", m.Fee.PoolDeduct.String()))
	return cosmos.Events{evt}, nil
}

// NewEventOutbound create a new instance of EventOutbound
func NewEventOutbound(inTxID common.TxID, tx common.Tx) *EventOutbound {
	return &EventOutbound{
		InTxID: inTxID,
		Tx:     tx,
	}
}

// Type return a string which represent the type of this event
func (m *EventOutbound) Type() string {
	return OutboundEventType
}

// Events return sdk events
func (m *EventOutbound) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("in_tx_id", m.InTxID.String()))
	evt = evt.AppendAttributes(m.Tx.ToAttributes()...)
	return cosmos.Events{evt}, nil
}

// NewEventTssKeygenMetric create a new EventTssMetric
func NewEventTssKeygenMetric(pubkey common.PubKey, medianDurationMS int64) *EventTssKeygenMetric {
	return &EventTssKeygenMetric{
		PubKey:           pubkey,
		MedianDurationMs: medianDurationMS,
	}
}

// Type  return a string which represent the type of this event
func (m *EventTssKeygenMetric) Type() string {
	return TSSKeygenMetricEventType
}

// Events return cosmos sdk events
func (m *EventTssKeygenMetric) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("pubkey", m.PubKey.String()),
		cosmos.NewAttribute("median_duration_ms", strconv.FormatInt(m.MedianDurationMs, 10)))
	return cosmos.Events{evt}, nil
}

// NewEventTssKeysignMetric create a new EventTssMetric
func NewEventTssKeysignMetric(txID common.TxID, medianDurationMS int64) *EventTssKeysignMetric {
	return &EventTssKeysignMetric{
		TxID:             txID,
		MedianDurationMs: medianDurationMS,
	}
}

// Type  return a string which represent the type of this event
func (m *EventTssKeysignMetric) Type() string {
	return TSSKeysignMetricEventType
}

// Events return cosmos sdk events
func (m *EventTssKeysignMetric) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("txid", m.TxID.String()),
		cosmos.NewAttribute("median_duration_ms", strconv.FormatInt(m.MedianDurationMs, 10)))
	return cosmos.Events{evt}, nil
}

// NewEventSlashPoint create a new slash point event
func NewEventSlashPoint(addr cosmos.AccAddress, slashPoints int64, reason string) *EventSlashPoint {
	return &EventSlashPoint{
		NodeAddress: addr,
		SlashPoints: slashPoints,
		Reason:      reason,
	}
}

// Type return a string which represent the type of this event
func (m *EventSlashPoint) Type() string {
	return SlashPointEventType
}

// Events return cosmos sdk events
func (m *EventSlashPoint) Events() (cosmos.Events, error) {
	evt := cosmos.NewEvent(m.Type(),
		cosmos.NewAttribute("node_address", m.NodeAddress.String()),
		cosmos.NewAttribute("slash_points", strconv.FormatInt(m.SlashPoints, 10)),
		cosmos.NewAttribute("reason", m.Reason))
	return cosmos.Events{evt}, nil
}
