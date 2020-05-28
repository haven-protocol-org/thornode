package types

import (
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/thornode/common"
	cosmos "gitlab.com/thorchain/thornode/common/cosmos"
)

type EventSuite struct{}

var _ = Suite(&EventSuite{})

func (s EventSuite) TestSwapEvent(c *C) {
	evt := NewEventSwap(
		common.BNBAsset,
		cosmos.NewUint(5),
		cosmos.NewUint(5),
		cosmos.NewUint(5),
		cosmos.ZeroUint(),
		GetRandomTx(),
	)
	c.Check(evt.Type(), Equals, "swap")
}

func (s EventSuite) TestStakeEvent(c *C) {
	evt := NewEventStake(
		common.BNBAsset,
		cosmos.NewUint(5),
		GetRandomRUNEAddress(),
		cosmos.NewUint(5),
		cosmos.NewUint(5),
		GetRandomTxHash(),
		GetRandomTxHash(),
	)
	c.Check(evt.Type(), Equals, "stake")
}

func (s EventSuite) TestUnstakeEvent(c *C) {
	evt := NewEventUnstake(
		common.BNBAsset,
		cosmos.NewUint(6),
		5000,
		cosmos.NewDec(0),
		GetRandomTx(),
	)
	c.Check(evt.Type(), Equals, "unstake")
}

func (s EventSuite) TestPool(c *C) {
	evt := NewEventPool(common.BNBAsset, Enabled)
	c.Check(evt.Type(), Equals, "pool")
	c.Check(evt.Pool.String(), Equals, common.BNBAsset.String())
	c.Check(evt.Status.String(), Equals, Enabled.String())
}

func (s EventSuite) TestReward(c *C) {
	evt := NewEventRewards(cosmos.NewUint(300), []PoolAmt{
		{common.BNBAsset, 30},
		{common.BTCAsset, 40},
	})
	c.Check(evt.Type(), Equals, "rewards")
	c.Check(evt.BondReward.String(), Equals, "300")
	c.Assert(evt.PoolRewards, HasLen, 2)
	c.Check(evt.PoolRewards[0].Asset.Equals(common.BNBAsset), Equals, true)
	c.Check(evt.PoolRewards[0].Amount, Equals, int64(30))
	c.Check(evt.PoolRewards[1].Asset.Equals(common.BTCAsset), Equals, true)
	c.Check(evt.PoolRewards[1].Amount, Equals, int64(40))
}

func (s EventSuite) TestSlash(c *C) {
	evt := NewEventSlash(common.BNBAsset, []PoolAmt{
		{common.BNBAsset, -20},
		{common.RuneAsset(), 30},
	})
	c.Check(evt.Type(), Equals, "slash")
	c.Check(evt.Pool, Equals, common.BNBAsset)
	c.Assert(evt.SlashAmount, HasLen, 2)
	c.Check(evt.SlashAmount[0].Asset, Equals, common.BNBAsset)
	c.Check(evt.SlashAmount[0].Amount, Equals, int64(-20))
	c.Check(evt.SlashAmount[1].Asset, Equals, common.RuneAsset())
	c.Check(evt.SlashAmount[1].Amount, Equals, int64(30))
}

func (s EventSuite) TestEventGas(c *C) {
	eg := NewEventGas()
	c.Assert(eg, NotNil)
	eg.UpsertGasPool(GasPool{
		Asset:    common.BNBAsset,
		AssetAmt: cosmos.NewUint(1000),
		RuneAmt:  cosmos.ZeroUint(),
	})
	c.Assert(eg.Pools, HasLen, 1)
	c.Assert(eg.Pools[0].Asset, Equals, common.BNBAsset)
	c.Assert(eg.Pools[0].RuneAmt.Equal(cosmos.ZeroUint()), Equals, true)
	c.Assert(eg.Pools[0].AssetAmt.Equal(cosmos.NewUint(1000)), Equals, true)

	eg.UpsertGasPool(GasPool{
		Asset:    common.BNBAsset,
		AssetAmt: cosmos.NewUint(1234),
		RuneAmt:  cosmos.NewUint(1024),
	})
	c.Assert(eg.Pools, HasLen, 1)
	c.Assert(eg.Pools[0].Asset, Equals, common.BNBAsset)
	c.Assert(eg.Pools[0].RuneAmt.Equal(cosmos.NewUint(1024)), Equals, true)
	c.Assert(eg.Pools[0].AssetAmt.Equal(cosmos.NewUint(2234)), Equals, true)

	eg.UpsertGasPool(GasPool{
		Asset:    common.BTCAsset,
		AssetAmt: cosmos.NewUint(1024),
		RuneAmt:  cosmos.ZeroUint(),
	})
	c.Assert(eg.Pools, HasLen, 2)
	c.Assert(eg.Pools[1].Asset, Equals, common.BTCAsset)
	c.Assert(eg.Pools[1].AssetAmt.Equal(cosmos.NewUint(1024)), Equals, true)
	c.Assert(eg.Pools[1].RuneAmt.Equal(cosmos.ZeroUint()), Equals, true)

	eg.UpsertGasPool(GasPool{
		Asset:    common.BTCAsset,
		AssetAmt: cosmos.ZeroUint(),
		RuneAmt:  cosmos.ZeroUint(),
	})

	c.Assert(eg.Pools, HasLen, 2)
	c.Assert(eg.Pools[1].Asset, Equals, common.BTCAsset)
	c.Assert(eg.Pools[1].AssetAmt.Equal(cosmos.NewUint(1024)), Equals, true)
	c.Assert(eg.Pools[1].RuneAmt.Equal(cosmos.ZeroUint()), Equals, true)

	eg.UpsertGasPool(GasPool{
		Asset:    common.BTCAsset,
		AssetAmt: cosmos.ZeroUint(),
		RuneAmt:  cosmos.NewUint(3333),
	})

	c.Assert(eg.Pools, HasLen, 2)
	c.Assert(eg.Pools[1].Asset, Equals, common.BTCAsset)
	c.Assert(eg.Pools[1].AssetAmt.Equal(cosmos.NewUint(1024)), Equals, true)
	c.Assert(eg.Pools[1].RuneAmt.Equal(cosmos.NewUint(3333)), Equals, true)
}

func (s EventSuite) TestEventFee(c *C) {
	event := NewEventFee(GetRandomTxHash(), common.Fee{
		Coins: common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(1024)),
		},
		PoolDeduct: cosmos.NewUint(1023),
	})
	c.Assert(event.Type(), Equals, FeeEventType)
	evts, err := event.Events()
	c.Assert(err, IsNil)
	c.Assert(evts, HasLen, 1)
}
