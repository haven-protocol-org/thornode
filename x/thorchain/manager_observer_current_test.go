package thorchain

import (
	"sort"

	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/thornode/common"
	cosmos "gitlab.com/thorchain/thornode/common/cosmos"
)

type ObserverManagerTestSuite struct{}

var _ = Suite(&ObserverManagerTestSuite{})

func (ObserverManagerTestSuite) TestObserverManager(c *C) {
	var err error
	ctx, k := setupKeeperForTest(c)
<<<<<<< HEAD:x/thorchain/manager_observer_v1_test.go
	mgr := NewObserverMgrV1()
=======
	mgr := newObserverMgrV1()
>>>>>>> b62de874e29856c2e4e9cef96197b20e6568e812:x/thorchain/manager_observer_current_test.go
	c.Assert(mgr, NotNil)
	mgr.BeginBlock()
	c.Check(mgr.List(), HasLen, 0)

	a1 := GetRandomBech32Addr()
	a2 := GetRandomBech32Addr()
	a3 := GetRandomBech32Addr()
	mgr.AppendObserver(common.BNBChain, []cosmos.AccAddress{
		a1, a2, a3,
	})
	c.Check(mgr.List(), HasLen, 3)
	mgr.AppendObserver(common.BTCChain, []cosmos.AccAddress{
		a1, a2,
	})
	c.Check(mgr.List(), HasLen, 2)
	addrs := mgr.List()
	// sort alphabetically
	sort.SliceStable(addrs, func(i, j int) bool { return addrs[i].String() > addrs[j].String() })
	expected := []cosmos.AccAddress{a1, a2}
	sort.SliceStable(expected, func(i, j int) bool { return expected[i].String() > expected[j].String() })
	c.Check(addrs, DeepEquals, expected)

	mgr.EndBlock(ctx, k)
	addrs, err = k.GetObservingAddresses(ctx)
	c.Assert(err, IsNil)
	c.Check(addrs, HasLen, 2)
	// sort alphabetically
	sort.SliceStable(addrs, func(i, j int) bool { return addrs[i].String() > addrs[j].String() })
	expected = []cosmos.AccAddress{a1, a2}
	sort.SliceStable(expected, func(i, j int) bool { return expected[i].String() > expected[j].String() })
	c.Check(addrs, DeepEquals, expected)
}
