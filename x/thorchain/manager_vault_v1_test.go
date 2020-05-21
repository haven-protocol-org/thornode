package thorchain

import (
	"errors"

	. "gopkg.in/check.v1"

	"github.com/blang/semver"

	"gitlab.com/thorchain/thornode/common"
	cosmos "gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
)

type VaultManagerTestSuite struct{}

var _ = Suite(&VaultManagerTestSuite{})

func (s *VaultManagerTestSuite) SetUpSuite(c *C) {
	SetupConfigForTest()
}

type TestRagnarokChainKeeper struct {
	KVStoreDummy
	activeVault Vault
	retireVault Vault
	yggVault    Vault
	pools       Pools
	stakers     []Staker
	na          NodeAccount
	err         error
}

func (k *TestRagnarokChainKeeper) ListNodeAccountsWithBond(_ cosmos.Context) (NodeAccounts, error) {
	return NodeAccounts{k.na}, k.err
}

func (k *TestRagnarokChainKeeper) ListActiveNodeAccounts(_ cosmos.Context) (NodeAccounts, error) {
	return NodeAccounts{k.na}, k.err
}

func (k *TestRagnarokChainKeeper) GetNodeAccount(ctx cosmos.Context, signer cosmos.AccAddress) (NodeAccount, error) {
	if k.na.NodeAddress.Equals(signer) {
		return k.na, nil
	}
	return NodeAccount{}, nil
}

func (k *TestRagnarokChainKeeper) GetAsgardVaultsByStatus(_ cosmos.Context, vt VaultStatus) (Vaults, error) {
	if vt == ActiveVault {
		return Vaults{k.activeVault}, k.err
	}
	return Vaults{k.retireVault}, k.err
}

func (k *TestRagnarokChainKeeper) VaultExists(_ cosmos.Context, _ common.PubKey) bool {
	return true
}

func (k *TestRagnarokChainKeeper) GetVault(_ cosmos.Context, _ common.PubKey) (Vault, error) {
	return k.yggVault, k.err
}

func (k *TestRagnarokChainKeeper) GetPools(_ cosmos.Context) (Pools, error) {
	return k.pools, k.err
}

func (k *TestRagnarokChainKeeper) GetPool(_ cosmos.Context, asset common.Asset) (Pool, error) {
	for _, pool := range k.pools {
		if pool.Asset.Equals(asset) {
			return pool, nil
		}
	}
	return Pool{}, errors.New("pool not found")
}

func (k *TestRagnarokChainKeeper) SetPool(_ cosmos.Context, pool Pool) error {
	for i, p := range k.pools {
		if p.Asset.Equals(pool.Asset) {
			k.pools[i] = pool
		}
	}
	return k.err
}

func (k *TestRagnarokChainKeeper) PoolExist(_ cosmos.Context, _ common.Asset) bool {
	return true
}

func (k *TestRagnarokChainKeeper) GetStakerIterator(ctx cosmos.Context, _ common.Asset) cosmos.Iterator {
	cdc := makeTestCodec()
	iter := NewDummyIterator()
	for _, staker := range k.stakers {
		iter.AddItem([]byte("key"), cdc.MustMarshalBinaryBare(staker))
	}
	return iter
}

func (k *TestRagnarokChainKeeper) GetStaker(_ cosmos.Context, asset common.Asset, addr common.Address) (Staker, error) {
	if asset.Equals(common.BTCAsset) {
		for i, staker := range k.stakers {
			if addr.Equals(staker.RuneAddress) {
				return k.stakers[i], k.err
			}
		}
	}
	return Staker{}, k.err
}

func (k *TestRagnarokChainKeeper) SetStaker(_ cosmos.Context, staker Staker) {
	for i, skr := range k.stakers {
		if staker.RuneAddress.Equals(skr.RuneAddress) {
			k.stakers[i] = staker
		}
	}
}

func (k *TestRagnarokChainKeeper) RemoveStaker(_ cosmos.Context, staker Staker) {
	for i, skr := range k.stakers {
		if staker.RuneAddress.Equals(skr.RuneAddress) {
			k.stakers[i] = staker
		}
	}
}

func (k *TestRagnarokChainKeeper) GetGas(_ cosmos.Context, _ common.Asset) ([]cosmos.Uint, error) {
	return []cosmos.Uint{cosmos.NewUint(10)}, k.err
}

func (k *TestRagnarokChainKeeper) GetLowestActiveVersion(_ cosmos.Context) semver.Version {
	return constants.SWVersion
}

func (k *TestRagnarokChainKeeper) AddFeeToReserve(_ cosmos.Context, _ cosmos.Uint) error {
	return k.err
}

func (k *TestRagnarokChainKeeper) UpsertEvent(_ cosmos.Context, _ Event) error {
	return k.err
}

func (k *TestRagnarokChainKeeper) IsActiveObserver(_ cosmos.Context, _ cosmos.AccAddress) bool {
	return true
}

func (s *VaultManagerTestSuite) TestRagnarokChain(c *C) {
	ctx, _ := setupKeeperForTest(c)
	ctx = ctx.WithBlockHeight(100000)
	ver := constants.SWVersion
	constAccessor := constants.GetConstantValues(ver)

	activeVault := GetRandomVault()
	retireVault := GetRandomVault()
	retireVault.Chains = common.Chains{common.BNBChain, common.BTCChain}
	yggVault := GetRandomVault()
	yggVault.Type = YggdrasilVault
	yggVault.Coins = common.Coins{
		common.NewCoin(common.BTCAsset, cosmos.NewUint(3*common.One)),
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(300*common.One)),
	}

	btcPool := NewPool()
	btcPool.Asset = common.BTCAsset
	btcPool.BalanceRune = cosmos.NewUint(1000 * common.One)
	btcPool.BalanceAsset = cosmos.NewUint(10 * common.One)
	btcPool.PoolUnits = cosmos.NewUint(1600)

	bnbPool := NewPool()
	bnbPool.Asset = common.BNBAsset
	bnbPool.BalanceRune = cosmos.NewUint(1000 * common.One)
	bnbPool.BalanceAsset = cosmos.NewUint(10 * common.One)
	bnbPool.PoolUnits = cosmos.NewUint(1600)

	addr := GetRandomRUNEAddress()
	stakers := []Staker{
		Staker{
			RuneAddress:     addr,
			LastStakeHeight: 5,
			Units:           btcPool.PoolUnits.QuoUint64(2),
			PendingRune:     cosmos.ZeroUint(),
		},
		Staker{
			RuneAddress:     GetRandomRUNEAddress(),
			LastStakeHeight: 10,
			Units:           btcPool.PoolUnits.QuoUint64(2),
			PendingRune:     cosmos.ZeroUint(),
		},
	}

	keeper := &TestRagnarokChainKeeper{
		na:          GetRandomNodeAccount(NodeActive),
		activeVault: activeVault,
		retireVault: retireVault,
		yggVault:    yggVault,
		pools:       Pools{bnbPool, btcPool},
		stakers:     stakers,
	}

	mgr := NewDummyMgr()

	vaultMgr := NewVaultMgrV1(keeper, mgr.TxOutStore(), mgr.EventMgr())

	err := vaultMgr.manageChains(ctx, mgr, constAccessor)
	c.Assert(err, IsNil)
	c.Check(keeper.pools[1].Asset.Equals(common.BTCAsset), Equals, true)
	c.Check(keeper.pools[1].PoolUnits.IsZero(), Equals, true, Commentf("%d\n", keeper.pools[1].PoolUnits.Uint64()))
	c.Check(keeper.pools[0].PoolUnits.Equal(cosmos.NewUint(1600)), Equals, true)
	for _, skr := range keeper.stakers {
		c.Check(skr.Units.IsZero(), Equals, true)
	}

	// ensure we have requested for ygg funds to be returned
	txOutStore := mgr.TxOutStore()
	c.Assert(err, IsNil)
	items, err := txOutStore.GetOutboundItems(ctx)
	c.Assert(err, IsNil)

	// 1 ygg return + 4 unstakes
	if common.RuneAsset().Chain.Equals(common.THORChain) {
		c.Check(items, HasLen, 3, Commentf("Len %d", items))
	} else {
		c.Check(items, HasLen, 5, Commentf("Len %d", items))
	}
	c.Check(items[0].Memo, Equals, NewYggdrasilReturn(ctx.BlockHeight()).String())
	c.Check(items[0].Chain.Equals(common.BTCChain), Equals, true)
}

func (s *VaultManagerTestSuite) TestUpdateVaultData(c *C) {
	ctx, k := setupKeeperForTest(c)
	ver := constants.SWVersion
	constAccessor := constants.GetConstantValues(ver)
	vd := NewVaultData()
	err := k.SetVaultData(ctx, vd)
	c.Assert(err, IsNil)

	mgr := NewDummyMgr()

	vaultMgr := NewVaultMgrV1(k, mgr.TxOutStore(), mgr.EventMgr())

	c.Assert(vaultMgr.UpdateVaultData(ctx, constAccessor, mgr.GasMgr(), mgr.EventMgr()), IsNil)

	// add something in vault
	vd.TotalReserve = cosmos.NewUint(common.One * 100)
	err = k.SetVaultData(ctx, vd)
	c.Assert(err, IsNil)
	c.Assert(vaultMgr.UpdateVaultData(ctx, constAccessor, mgr.GasMgr(), mgr.EventMgr()), IsNil)
}