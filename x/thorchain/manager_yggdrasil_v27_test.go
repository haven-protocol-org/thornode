package thorchain

import (
	"github.com/blang/semver"
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	"gitlab.com/thorchain/thornode/x/thorchain/keeper"
)

type YggdrasilManagerV27Suite struct{}

var _ = Suite(&YggdrasilManagerV27Suite{})

func (s YggdrasilManagerV27Suite) TestCalcTargetAmounts(c *C) {
	var pools []Pool
	p := NewPool()
	p.Asset = common.BNBAsset
	p.BalanceRune = cosmos.NewUint(1000 * common.One)
	p.BalanceAsset = cosmos.NewUint(500 * common.One)
	pools = append(pools, p)

	p = NewPool()
	p.Asset = common.BTCAsset
	p.BalanceRune = cosmos.NewUint(3000 * common.One)
	p.BalanceAsset = cosmos.NewUint(225 * common.One)
	pools = append(pools, p)

	ygg := GetRandomVault()
	ygg.Type = YggdrasilVault

	totalBond := cosmos.NewUint(8000 * common.One)
	bond := cosmos.NewUint(200 * common.One)
	ymgr := NewYggMgrV27(keeper.KVStoreDummy{})
	yggFundLimit := cosmos.NewUint(50)
	coins, err := ymgr.calcTargetYggCoins(pools, ygg, bond, totalBond, yggFundLimit)
	c.Assert(err, IsNil)
	c.Assert(coins, HasLen, 2)
	c.Check(coins[0].Asset.String(), Equals, common.BNBAsset.String())
	c.Check(coins[0].Amount.Uint64(), Equals, cosmos.NewUint(6.25*common.One).Uint64(), Commentf("%d vs %d", coins[0].Amount.Uint64(), cosmos.NewUint(6.25*common.One).Uint64()))
	c.Check(coins[1].Asset.String(), Equals, common.BTCAsset.String())
	c.Check(coins[1].Amount.Uint64(), Equals, cosmos.NewUint(2.8125*common.One).Uint64(), Commentf("%d vs %d", coins[1].Amount.Uint64(), cosmos.NewUint(2.8125*common.One).Uint64()))
}

func (s YggdrasilManagerV27Suite) TestCalcTargetAmounts2(c *C) {
	// Adding specific test per PR request
	// https://gitlab.com/thorchain/thornode/merge_requests/246#note_241913460
	var pools []Pool
	p := NewPool()
	p.Asset = common.BNBAsset
	p.BalanceRune = cosmos.NewUint(1000000 * common.One)
	p.BalanceAsset = cosmos.NewUint(1 * common.One)
	pools = append(pools, p)

	ygg := GetRandomVault()
	ygg.Type = YggdrasilVault

	totalBond := cosmos.NewUint(3000000 * common.One)
	bond := cosmos.NewUint(1000000 * common.One)
	ymgr := NewYggMgrV27(keeper.KVStoreDummy{})
	yggFundLimit := cosmos.NewUint(50)
	coins, err := ymgr.calcTargetYggCoins(pools, ygg, bond, totalBond, yggFundLimit)
	c.Assert(err, IsNil)
	c.Assert(coins, HasLen, 1)
	c.Check(coins[0].Asset.String(), Equals, common.BNBAsset.String())
	c.Check(coins[0].Amount.Uint64(), Equals, cosmos.NewUint(0.16666667*common.One).Uint64(), Commentf("%d vs %d", coins[0].Amount.Uint64(), cosmos.NewUint(0.16666667*common.One).Uint64()))
}

func (s YggdrasilManagerV27Suite) TestCalcTargetAmounts3(c *C) {
	// pre populate the yggdrasil vault with funds already, ensure we don't
	// double up on funds.
	var pools []Pool
	p := NewPool()
	p.Asset = common.BNBAsset
	p.BalanceRune = cosmos.NewUint(1000 * common.One)
	p.BalanceAsset = cosmos.NewUint(500 * common.One)
	pools = append(pools, p)

	p = NewPool()
	p.Asset = common.BTCAsset
	p.BalanceRune = cosmos.NewUint(3000 * common.One)
	p.BalanceAsset = cosmos.NewUint(225 * common.One)
	pools = append(pools, p)

	ygg := GetRandomVault()
	ygg.Type = YggdrasilVault
	ygg.Coins = common.Coins{
		common.NewCoin(common.BNBAsset, cosmos.NewUint(6.25*common.One)),
		common.NewCoin(common.BTCAsset, cosmos.NewUint(1.8125*common.One)),
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(30*common.One)),
	}

	totalBond := cosmos.NewUint(8000 * common.One)
	bond := cosmos.NewUint(200 * common.One)
	ymgr := NewYggMgrV27(keeper.KVStoreDummy{})
	yggFundLimit := cosmos.NewUint(50)
	coins, err := ymgr.calcTargetYggCoins(pools, ygg, bond, totalBond, yggFundLimit)
	c.Assert(err, IsNil)
	c.Assert(coins, HasLen, 1, Commentf("%d", len(coins)))
	c.Check(coins[0].Asset.String(), Equals, common.BTCAsset.String())
	c.Check(coins[0].Amount.Uint64(), Equals, cosmos.NewUint(1*common.One).Uint64(), Commentf("%d vs %d", coins[0].Amount.Uint64(), cosmos.NewUint(2.8125*common.One).Uint64()))
}

func (s YggdrasilManagerV27Suite) TestCalcTargetAmounts4(c *C) {
	// test under bonded scenario
	var pools []Pool
	p := NewPool()
	p.Asset = common.BNBAsset
	p.BalanceRune = cosmos.NewUint(1000 * common.One)
	p.BalanceAsset = cosmos.NewUint(500 * common.One)
	pools = append(pools, p)

	p = NewPool()
	p.Asset = common.BTCAsset
	p.BalanceRune = cosmos.NewUint(3000 * common.One)
	p.BalanceAsset = cosmos.NewUint(225 * common.One)
	pools = append(pools, p)

	ygg := GetRandomVault()
	ygg.Type = YggdrasilVault
	ygg.Coins = common.Coins{
		common.NewCoin(common.BNBAsset, cosmos.NewUint(6.25*common.One)),
		common.NewCoin(common.BTCAsset, cosmos.NewUint(1.8125*common.One)),
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(30*common.One)),
	}

	totalBond := cosmos.NewUint(2000 * common.One)
	bond := cosmos.NewUint(200 * common.One)
	ymgr := NewYggMgrV27(keeper.KVStoreDummy{})
	yggFundLimit := cosmos.NewUint(50)
	coins, err := ymgr.calcTargetYggCoins(pools, ygg, bond, totalBond, yggFundLimit)
	c.Assert(err, IsNil)
	c.Assert(coins, HasLen, 1, Commentf("%d", len(coins)))
	c.Check(coins[0].Asset.String(), Equals, common.BTCAsset.String())
	c.Check(coins[0].Amount.Uint64(), Equals, cosmos.NewUint(1*common.One).Uint64(), Commentf("%d vs %d", coins[0].Amount.Uint64(), cosmos.NewUint(2.8125*common.One).Uint64()))
}

func (s YggdrasilManagerV27Suite) TestFund(c *C) {
	ctx, k := setupKeeperForTest(c)
	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(10000*common.One)),
	}
	k.SetVault(ctx, vault)
	mgr := NewDummyMgr()

	// setup 6 active nodes
	for i := 0; i < 6; i++ {
		na := GetRandomNodeAccount(NodeActive)
		na.Bond = cosmos.NewUint(common.One * 1000000)
		c.Assert(k.SetNodeAccount(ctx, na), IsNil)
	}
	ver := semver.MustParse("0.13.0")
	constAccessor := constants.GetConstantValues(ver)
	ymgr := NewYggMgrV27(k)
	err := ymgr.Fund(ctx, mgr, constAccessor)
	c.Assert(err, IsNil)
	na1 := GetRandomNodeAccount(NodeActive)
	na1.Bond = cosmos.NewUint(1000000 * common.One)
	c.Assert(k.SetNodeAccount(ctx, na1), IsNil)
	bnbPool := NewPool()
	bnbPool.Asset = common.BNBAsset
	bnbPool.BalanceAsset = cosmos.NewUint(100000 * common.One)
	bnbPool.BalanceRune = cosmos.NewUint(100000 * common.One)
	c.Assert(k.SetPool(ctx, bnbPool), IsNil)
	err1 := ymgr.Fund(ctx, mgr, constAccessor)
	c.Assert(err1, IsNil)
	items, err := mgr.TxOutStore().GetOutboundItems(ctx)
	c.Assert(err, IsNil)
	c.Assert(items, HasLen, 1)
}

func (s YggdrasilManagerV27Suite) TestNotAvailablePoolAssetWillNotFundYggdrasil(c *C) {
	ctx, k := setupKeeperForTest(c)
	vault := GetRandomVault()
	asset, err := common.NewAsset("BNB.BUSD-BD1")
	c.Assert(err, IsNil)
	vault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(10000*common.One)),
		common.NewCoin(asset, cosmos.NewUint(10000*common.One)),
	}
	k.SetVault(ctx, vault)
	mgr := NewDummyMgr()

	// setup 6 active nodes
	for i := 0; i < 6; i++ {
		na := GetRandomNodeAccount(NodeActive)
		na.Bond = cosmos.NewUint(common.One * 1000000)
		c.Assert(k.SetNodeAccount(ctx, na), IsNil)
	}
	ver := semver.MustParse("0.16.0")
	constAccessor := constants.GetConstantValues(ver)
	ymgr := NewYggMgrV27(k)
	err = ymgr.Fund(ctx, mgr, constAccessor)
	c.Assert(err, IsNil)
	na1 := GetRandomNodeAccount(NodeActive)
	na1.Bond = cosmos.NewUint(1000000 * common.One)
	c.Assert(k.SetNodeAccount(ctx, na1), IsNil)
	bnbPool := NewPool()
	bnbPool.Asset = common.BNBAsset
	bnbPool.BalanceAsset = cosmos.NewUint(100000 * common.One)
	bnbPool.BalanceRune = cosmos.NewUint(100000 * common.One)
	c.Assert(k.SetPool(ctx, bnbPool), IsNil)

	busdPool := NewPool()
	busdPool.Asset = asset
	busdPool.BalanceRune = cosmos.NewUint(100000 * common.One)
	busdPool.BalanceAsset = cosmos.NewUint(10000 * common.One)
	busdPool.Status = PoolStaged
	c.Assert(k.SetPool(ctx, busdPool), IsNil)

	err1 := ymgr.Fund(ctx, mgr, constAccessor)
	c.Assert(err1, IsNil)
	items, err := mgr.TxOutStore().GetOutboundItems(ctx)
	c.Assert(err, IsNil)
	c.Assert(items, HasLen, 1)
}

func (s YggdrasilManagerV27Suite) TestAbandonYggdrasil(c *C) {
	ctx, k := setupKeeperForTest(c)
	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(10000*common.One)),
	}
	k.SetVault(ctx, vault)
	mgr := NewManagers(k)
	mgr.BeginBlock(ctx)
	// add a queue , if we don't have pool , we don't know how to slash
	bnbPool := NewPool()
	bnbPool.Asset = common.BNBAsset
	bnbPool.BalanceRune = cosmos.NewUint(1000 * common.One)
	bnbPool.BalanceAsset = cosmos.NewUint(1000 * common.One)
	c.Assert(k.SetPool(ctx, bnbPool), IsNil)
	// setup 6 active nodes ,  so it will fund yggdrasil
	for i := 0; i < 6; i++ {
		na := GetRandomNodeAccount(NodeActive)
		na.Bond = cosmos.NewUint(common.One * 1000000)
		FundModule(c, ctx, k, BondName, na.Bond.Uint64())
		c.Assert(k.SetNodeAccount(ctx, na), IsNil)
	}
	naDisabled := GetRandomNodeAccount(NodeDisabled)
	naDisabled.RequestedToLeave = true
	naDisabled.Bond = cosmos.NewUint(common.One * 1000000)
	FundModule(c, ctx, k, BondName, naDisabled.Bond.Uint64())
	c.Assert(k.SetNodeAccount(ctx, naDisabled), IsNil)

	yggdrasilVault := GetRandomVault()
	yggdrasilVault.PubKey = naDisabled.PubKeySet.Secp256k1
	yggdrasilVault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(250*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(200*common.One)),
	}
	yggdrasilVault.Type = YggdrasilVault
	yggdrasilVault.Status = ActiveVault
	c.Assert(k.SetVault(ctx, yggdrasilVault), IsNil)
	ver := semver.MustParse("0.13.0")
	constAccessor := constants.GetConstantValues(ver)
	ymgr := NewYggMgrV27(k)
	err := ymgr.Fund(ctx, mgr, constAccessor)
	c.Assert(err, IsNil)
	// make sure the yggdrasil vault had been removed
	c.Assert(k.VaultExists(ctx, naDisabled.PubKeySet.Secp256k1), Equals, false)
	// make sure the node account had been slashed with bond
	naDisabled, err = k.GetNodeAccount(ctx, naDisabled.NodeAddress)
	c.Assert(err, IsNil)
	c.Assert(naDisabled.Bond.Equal(cosmos.NewUint(999325*common.One)), Equals, true)
}

func (s YggdrasilManagerV27Suite) TestAbandonYggdrasilWithDifferentConditions(c *C) {
	ctx, k := setupKeeperForTest(c)
	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(10000*common.One)),
	}
	k.SetVault(ctx, vault)
	mgr := NewManagers(k)
	mgr.BeginBlock(ctx)
	// add a queue , if we don't have pool , we don't know how to slash
	bnbPool := NewPool()
	bnbPool.Asset = common.BNBAsset
	bnbPool.BalanceRune = cosmos.NewUint(1000 * common.One)
	bnbPool.BalanceAsset = cosmos.NewUint(1000 * common.One)
	c.Assert(k.SetPool(ctx, bnbPool), IsNil)
	// setup 6 active nodes ,  so it will fund yggdrasil
	for i := 0; i < 6; i++ {
		na := GetRandomNodeAccount(NodeActive)
		na.Bond = cosmos.NewUint(common.One * 1000000)
		c.Assert(k.SetNodeAccount(ctx, na), IsNil)
	}
	naDisabled := GetRandomNodeAccount(NodeDisabled)
	naDisabled.RequestedToLeave = true
	c.Assert(k.SetNodeAccount(ctx, naDisabled), IsNil)

	yggdrasilVault := GetRandomVault()
	yggdrasilVault.PubKey = naDisabled.PubKeySet.Secp256k1
	yggdrasilVault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(250*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(200*common.One)),
	}
	yggdrasilVault.Type = YggdrasilVault
	yggdrasilVault.Status = ActiveVault
	c.Assert(k.SetVault(ctx, yggdrasilVault), IsNil)

	kh := &abandonYggdrasilTestHelper{
		Keeper:                       k,
		failToGetAsgardVaultByStatus: true,
	}
	ymgr := NewYggMgrV27(kh)
	c.Assert(ymgr.abandonYggdrasilVaults(ctx, mgr), NotNil)

	kh = &abandonYggdrasilTestHelper{
		Keeper:               k,
		failToGetNodeAccount: true,
	}
	ymgr = NewYggMgrV27(kh)
	c.Assert(ymgr.abandonYggdrasilVaults(ctx, mgr), IsNil)
	c.Assert(k.VaultExists(ctx, naDisabled.PubKeySet.Secp256k1), Equals, true)

	// when bond is zero , it shouldn't do anything
	naDisabled.Bond = cosmos.ZeroUint()
	c.Assert(k.SetNodeAccount(ctx, naDisabled), IsNil)
	ymgr = NewYggMgrV27(k)
	c.Assert(ymgr.abandonYggdrasilVaults(ctx, mgr), IsNil)
	c.Assert(k.VaultExists(ctx, naDisabled.PubKeySet.Secp256k1), Equals, true)

	// when Node account belongs to one of the retiring vault should not slash yet
	naDisabled.Bond = cosmos.NewUint(1000 * common.One)
	c.Assert(k.SetNodeAccount(ctx, naDisabled), IsNil)
	asgardVault := GetRandomVault()
	asgardVault.Status = RetiringVault
	asgardVault.Type = AsgardVault
	asgardVault.Membership = common.PubKeys{
		GetRandomPubKey(),
		naDisabled.PubKeySet.Secp256k1,
	}.Strings()
	c.Assert(k.SetVault(ctx, asgardVault), IsNil)

	ymgr = NewYggMgrV27(k)
	c.Assert(ymgr.abandonYggdrasilVaults(ctx, mgr), IsNil)
	c.Assert(k.VaultExists(ctx, naDisabled.PubKeySet.Secp256k1), Equals, true)
}