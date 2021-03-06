package thorchain

import (
	"errors"
	"os"

	"github.com/blang/semver"
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	"gitlab.com/thorchain/thornode/x/thorchain/keeper"
	"gitlab.com/thorchain/thornode/x/thorchain/types"
)

type SwapSuite struct{}

var _ = Suite(&SwapSuite{})

func (s *SwapSuite) SetUpSuite(c *C) {
	err := os.Setenv("NET", "other")
	c.Assert(err, IsNil)
	SetupConfigForTest()
}

type TestSwapKeeper struct {
	keeper.KVStoreDummy
}

func (k *TestSwapKeeper) PoolExist(ctx cosmos.Context, asset common.Asset) bool {
	if asset.Equals(common.Asset{Chain: common.BNBChain, Symbol: "NOTEXIST", Ticker: "NOTEXIST"}) {
		return false
	}
	return true
}

func (k *TestSwapKeeper) GetPool(ctx cosmos.Context, asset common.Asset) (types.Pool, error) {
	if asset.Equals(common.Asset{Chain: common.BNBChain, Symbol: "NOTEXIST", Ticker: "NOTEXIST"}) {
		return types.Pool{}, nil
	} else if asset.Equals(common.BCHAsset) {
		return types.Pool{
			BalanceRune:  cosmos.NewUint(100).MulUint64(common.One),
			BalanceAsset: cosmos.NewUint(100).MulUint64(common.One),
			PoolUnits:    cosmos.NewUint(100).MulUint64(common.One),
			Status:       PoolStaged,
			Asset:        asset,
		}, nil
	} else {
		return types.Pool{
			BalanceRune:  cosmos.NewUint(100).MulUint64(common.One),
			BalanceAsset: cosmos.NewUint(100).MulUint64(common.One),
			PoolUnits:    cosmos.NewUint(100).MulUint64(common.One),
			Status:       PoolAvailable,
			Asset:        asset,
		}, nil
	}
}
func (k *TestSwapKeeper) SetPool(ctx cosmos.Context, ps types.Pool) error { return nil }

func (k *TestSwapKeeper) GetLiquidityProvider(ctx cosmos.Context, asset common.Asset, addr common.Address) (types.LiquidityProvider, error) {
	if asset.Equals(common.Asset{Chain: common.BNBChain, Symbol: "NOTEXISTSTICKER", Ticker: "NOTEXISTSTICKER"}) {
		return types.LiquidityProvider{}, errors.New("you asked for it")
	}
	return LiquidityProvider{
		Asset:        asset,
		RuneAddress:  addr,
		AssetAddress: addr,
		Units:        cosmos.NewUint(100),
		PendingRune:  cosmos.ZeroUint(),
	}, nil
}

func (k *TestSwapKeeper) SetLiquidityProvider(ctx cosmos.Context, ps types.LiquidityProvider) {}

func (k *TestSwapKeeper) AddToLiquidityFees(ctx cosmos.Context, asset common.Asset, fs cosmos.Uint) error {
	return nil
}

func (k *TestSwapKeeper) GetLowestActiveVersion(ctx cosmos.Context) semver.Version {
	return constants.SWVersion
}

func (k *TestSwapKeeper) AddFeeToReserve(ctx cosmos.Context, fee cosmos.Uint) error { return nil }

func (k *TestSwapKeeper) GetGas(ctx cosmos.Context, _ common.Asset) ([]cosmos.Uint, error) {
	return []cosmos.Uint{cosmos.NewUint(37500), cosmos.NewUint(30000)}, nil
}

func (k *TestSwapKeeper) GetAsgardVaultsByStatus(ctx cosmos.Context, status VaultStatus) (Vaults, error) {
	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.BNBAsset, cosmos.NewUint(10000*common.One)),
	}
	return Vaults{
		vault,
	}, nil
}

func (k *TestSwapKeeper) GetObservedTxInVoter(ctx cosmos.Context, hash common.TxID) (ObservedTxVoter, error) {
	return ObservedTxVoter{
		TxID: hash,
	}, nil
}

func (k *TestSwapKeeper) ListActiveNodeAccounts(ctx cosmos.Context) (NodeAccounts, error) {
	return NodeAccounts{}, nil
}

func (k *TestSwapKeeper) GetBlockOut(ctx cosmos.Context) (*TxOut, error) {
	return NewTxOut(ctx.BlockHeight()), nil
}

func (k *TestSwapKeeper) GetTxOut(ctx cosmos.Context, _ int64) (*TxOut, error) {
	return NewTxOut(ctx.BlockHeight()), nil
}

func (k *TestSwapKeeper) GetLeastSecure(ctx cosmos.Context, vaults Vaults, _ int64) Vault {
	return vaults[0]
}

func (k TestSwapKeeper) SortBySecurity(_ cosmos.Context, vaults Vaults, _ int64) Vaults {
	return vaults
}
func (k *TestSwapKeeper) AppendTxOut(_ cosmos.Context, _ int64, _ TxOutItem) error { return nil }
func (k *TestSwapKeeper) GetNetworkFee(ctx cosmos.Context, chain common.Chain) (NetworkFee, error) {
	if chain.Equals(common.BNBChain) {
		return NetworkFee{
			Chain:              common.BNBChain,
			TransactionSize:    1,
			TransactionFeeRate: 37500,
		}, nil
	}
	if chain.Equals(common.THORChain) {
		return NetworkFee{
			Chain:              common.THORChain,
			TransactionSize:    1,
			TransactionFeeRate: 1_00000000,
		}, nil
	}
	return NetworkFee{}, kaboom
}

func (k *TestSwapKeeper) SendFromModuleToModule(ctx cosmos.Context, from, to string, coin common.Coins) error {
	return nil
}

func (k *TestSwapKeeper) BurnFromModule(ctx cosmos.Context, module string, coin common.Coin) error {
	return nil
}

func (k *TestSwapKeeper) MintToModule(ctx cosmos.Context, module string, coin common.Coin) error {
	return nil
}

func (s *SwapSuite) TestSwap(c *C) {
	poolStorage := &TestSwapKeeper{}
	ctx, _ := setupKeeperForTest(c)
	inputs := []struct {
		name          string
		requestTxHash common.TxID
		source        common.Asset
		target        common.Asset
		amount        cosmos.Uint
		requester     common.Address
		destination   common.Address
		returnAmount  cosmos.Uint
		tradeTarget   cosmos.Uint
		expectedErr   error
		events        int
	}{
		{
			name:          "empty-source",
			requestTxHash: "hash",
			source:        common.Asset{},
			target:        common.BNBAsset,
			amount:        cosmos.NewUint(100 * common.One),
			requester:     "tester",
			destination:   "whatever",
			returnAmount:  cosmos.ZeroUint(),
			expectedErr:   errors.New("Denom cannot be empty"),
		},
		{
			name:          "empty-target",
			requestTxHash: "hash",
			source:        common.RuneAsset(),
			target:        common.Asset{},
			amount:        cosmos.NewUint(100 * common.One),
			requester:     "tester",
			destination:   "whatever",
			returnAmount:  cosmos.ZeroUint(),
			expectedErr:   errors.New("target is empty"),
		},
		{
			name:          "empty-requestTxHash",
			requestTxHash: "",
			source:        common.RuneAsset(),
			target:        common.BNBAsset,
			amount:        cosmos.NewUint(100 * common.One),
			requester:     "tester",
			destination:   "whatever",
			returnAmount:  cosmos.ZeroUint(),
			expectedErr:   errors.New("Tx ID cannot be empty"),
		},
		{
			name:          "empty-amount",
			requestTxHash: "hash",
			source:        common.RuneAsset(),
			target:        common.BNBAsset,
			amount:        cosmos.ZeroUint(),
			requester:     "tester",
			destination:   "whatever",
			returnAmount:  cosmos.ZeroUint(),
			expectedErr:   errors.New("Amount cannot be zero"),
		},
		{
			name:          "empty-requester",
			requestTxHash: "hash",
			source:        common.RuneAsset(),
			target:        common.BNBAsset,
			amount:        cosmos.NewUint(100 * common.One),
			requester:     "",
			destination:   "whatever",
			returnAmount:  cosmos.ZeroUint(),
			expectedErr:   errors.New("from address cannot be empty"),
		},
		{
			name:          "empty-destination",
			requestTxHash: "hash",
			source:        common.RuneAsset(),
			target:        common.BNBAsset,
			amount:        cosmos.NewUint(100 * common.One),
			requester:     GetRandomBNBAddress(),
			destination:   "",
			returnAmount:  cosmos.ZeroUint(),
			expectedErr:   errors.New("to address cannot be empty"),
		},
		{
			name:          "pool-not-exist",
			requestTxHash: "hash",
			source:        common.Asset{Chain: common.BNBChain, Ticker: "NOTEXIST", Symbol: "NOTEXIST"},
			target:        common.RuneAsset(),
			amount:        cosmos.NewUint(100 * common.One),
			requester:     GetRandomBNBAddress(),
			destination:   GetRandomBNBAddress(),
			tradeTarget:   cosmos.NewUint(110000000),
			returnAmount:  cosmos.ZeroUint(),
			expectedErr:   errors.New("BNB.NOTEXIST pool doesn't exist"),
		},
		{
			name:          "pool-not-exist-1",
			requestTxHash: "hash",
			source:        common.RuneAsset(),
			target:        common.Asset{Chain: common.BNBChain, Ticker: "NOTEXIST", Symbol: "NOTEXIST"},
			amount:        cosmos.NewUint(100 * common.One),
			requester:     "tester",
			destination:   "don'tknow",
			tradeTarget:   cosmos.NewUint(120000000),
			returnAmount:  cosmos.ZeroUint(),
			expectedErr:   errors.New("BNB.NOTEXIST pool doesn't exist"),
		},
		{
			name:          "swap-cross-chain-different-address",
			requestTxHash: "hash",
			source:        common.RuneAsset(),
			target:        common.BTCAsset,
			amount:        cosmos.NewUint(50 * common.One),
			requester:     "tester",
			destination:   GetRandomBNBAddress(),
			returnAmount:  cosmos.ZeroUint(),
			tradeTarget:   cosmos.ZeroUint(),
			expectedErr:   errors.New("destination address is not a valid BTC address"),
			events:        1,
		},
		{
			name:          "swap-no-global-sliplimit",
			requestTxHash: "hash",
			source:        common.RuneAsset(),
			target:        common.BNBAsset,
			amount:        cosmos.NewUint(50 * common.One),
			requester:     "tester",
			destination:   GetRandomBNBAddress(),
			returnAmount:  cosmos.NewUint(2222222222),
			tradeTarget:   cosmos.ZeroUint(),
			expectedErr:   nil,
			events:        1,
		},
		{
			name:          "swap-over-trade-sliplimit",
			requestTxHash: "hash",
			source:        common.RuneAsset(),
			target:        common.BNBAsset,
			amount:        cosmos.NewUint(9 * common.One),
			requester:     "tester",
			destination:   GetRandomBNBAddress(),
			returnAmount:  cosmos.ZeroUint(),
			tradeTarget:   cosmos.NewUint(9 * common.One),
			expectedErr:   errors.New("emit asset 757511993 less than price limit 900000000"),
		},
		{
			name:          "swap-no-target-price-no-protection",
			requestTxHash: "hash",
			source:        common.RuneAsset(),
			target:        common.BNBAsset,
			amount:        cosmos.NewUint(8 * common.One),
			requester:     "tester",
			destination:   GetRandomBNBAddress(),
			returnAmount:  cosmos.NewUint(685871056),
			tradeTarget:   cosmos.ZeroUint(),
			expectedErr:   nil,
			events:        1,
		},
		{
			name:          "swap",
			requestTxHash: "hash",
			source:        common.RuneAsset(),
			target:        common.BNBAsset,
			amount:        cosmos.NewUint(5 * common.One),
			requester:     "tester",
			destination:   GetRandomBNBAddress(),
			returnAmount:  cosmos.NewUint(453514739),
			tradeTarget:   cosmos.NewUint(453514738),
			expectedErr:   nil,
			events:        1,
		},
		{
			name:          "double-swap",
			requestTxHash: "hash",
			source:        common.Asset{Chain: common.BTCChain, Ticker: "BTC", Symbol: "BTC"},
			target:        common.BNBAsset,
			amount:        cosmos.NewUint(5 * common.One),
			requester:     "tester",
			destination:   GetRandomBNBAddress(),
			returnAmount:  cosmos.NewUint(415017809),
			tradeTarget:   cosmos.NewUint(415017809),
			expectedErr:   nil,
			events:        2,
		},
		{
			name:          "swap-synth-to-rune-when-pool-is-not-available",
			requestTxHash: "hash",
			source:        common.BCHAsset.GetSyntheticAsset(),
			target:        common.RuneAsset(),
			amount:        cosmos.NewUint(5 * common.One),
			requester:     "tester",
			destination:   GetRandomTHORAddress(),
			returnAmount:  cosmos.NewUint(475907198),
			tradeTarget:   cosmos.NewUint(453514738),
			expectedErr:   nil,
			events:        1,
		},
	}

	for _, item := range inputs {
		c.Logf("test name:%s", item.name)
		tx := common.NewTx(
			item.requestTxHash,
			item.requester,
			item.destination,
			common.Coins{
				common.NewCoin(item.source, item.amount),
			},
			BNBGasFeeSingleton,
			"",
		)
		tx.Chain = common.BNBChain
		m := NewManagers(poolStorage)
		m.BeginBlock(ctx)
		m.txOutStore = NewTxStoreDummy()

		amount, evts, err := swap(ctx, poolStorage, tx, item.target, item.destination, item.tradeTarget, cosmos.NewUint(1000_000), 2, m)
		if item.expectedErr == nil {
			c.Assert(err, IsNil)
			c.Assert(evts, HasLen, item.events)
		} else {
			c.Assert(err, NotNil, Commentf("Expected: %s, got nil", item.expectedErr.Error()))
			c.Assert(err.Error(), Equals, item.expectedErr.Error())
		}

		c.Logf("expected amount:%s, actual amount:%s", item.returnAmount, amount)
		c.Check(item.returnAmount.Uint64(), Equals, amount.Uint64())

	}
}

func (s SwapSuite) TestValidatePools(c *C) {
	keeper := &TestSwapKeeper{}
	ctx, _ := setupKeeperForTest(c)
	c.Check(validatePools(ctx, keeper, common.RuneAsset()), IsNil)
	c.Check(validatePools(ctx, keeper, common.Asset{Chain: common.BNBChain, Ticker: "NOTEXIST", Symbol: "NOTEXIST"}), NotNil)
}

func (s SwapSuite) TestValidateMessage(c *C) {
	c.Check(validateMessage(
		common.NewTx(
			GetRandomTxHash(),
			GetRandomBNBAddress(),
			GetRandomBNBAddress(),
			common.Coins{
				common.NewCoin(common.RuneAsset(), cosmos.NewUint(3429850000)),
			},
			BNBGasFeeSingleton,
			"",
		),
		common.BNBAsset,
		"bnbYYY",
	), IsNil)
	c.Check(validateMessage(
		common.NewTx(
			"",
			GetRandomBNBAddress(),
			GetRandomBNBAddress(),
			common.Coins{
				common.NewCoin(common.RuneAsset(), cosmos.NewUint(3429850000)),
			},
			BNBGasFeeSingleton,
			"",
		),
		common.BNBAsset,
		"bnbYYY",
	), NotNil)
	c.Check(validateMessage(
		common.NewTx(
			GetRandomTxHash(),
			GetRandomBNBAddress(),
			GetRandomBNBAddress(),
			common.Coins{
				common.NewCoin(common.Asset{}, cosmos.NewUint(3429850000)),
			},
			BNBGasFeeSingleton,
			"",
		),
		common.BNBAsset,
		"bnbYYY",
	), NotNil)
	c.Check(validateMessage(
		common.NewTx(
			GetRandomTxHash(),
			GetRandomBNBAddress(),
			GetRandomBNBAddress(),
			common.Coins{
				common.NewCoin(common.RuneAsset(), cosmos.NewUint(3429850000)),
			},
			BNBGasFeeSingleton,
			"",
		),
		common.Asset{},
		"bnbYYY",
	), NotNil)
	c.Check(validateMessage(
		common.NewTx(
			GetRandomTxHash(),
			GetRandomBNBAddress(),
			GetRandomBNBAddress(),
			common.Coins{
				common.NewCoin(common.RuneAsset(), cosmos.ZeroUint()),
			},
			BNBGasFeeSingleton,
			"",
		),
		common.BNBAsset,
		"bnbYYY",
	), NotNil)
	c.Check(validateMessage(
		common.NewTx(
			GetRandomTxHash(),
			"",
			GetRandomBNBAddress(),
			common.Coins{
				common.NewCoin(common.RuneAsset(), cosmos.NewUint(3429850000)),
			},
			BNBGasFeeSingleton,
			"",
		),
		common.BNBAsset,
		"bnbYYY",
	), NotNil)
	c.Check(validateMessage(
		common.NewTx(
			GetRandomTxHash(),
			GetRandomBNBAddress(),
			GetRandomBNBAddress(),
			common.Coins{
				common.NewCoin(common.RuneAsset(), cosmos.NewUint(3429850000)),
			},
			BNBGasFeeSingleton,
			"",
		),
		common.BNBAsset,
		"",
	), NotNil)
}

func (s SwapSuite) TestCalculators(c *C) {
	X := cosmos.NewUint(100 * common.One)
	x := cosmos.NewUint(10 * common.One)
	Y := cosmos.NewUint(100 * common.One)

	// These calculations are verified by using the spreadsheet
	// https://docs.google.com/spreadsheets/d/1wJHYBRKBdw_WP7nUyVnkySPkOmPUNoiRGsEqgBVVXKU/edit#gid=0
	c.Check(calcAssetEmission(X, x, Y).Uint64(), Equals, uint64(826446280))
	c.Check(calcLiquidityFee(X, x, Y).Uint64(), Equals, uint64(82644628))
	c.Check(calcSwapSlip(X, x).Uint64(), Equals, uint64(909), Commentf("%d", calcSwapSlip(X, x).Uint64()))

	// side of the pool is zero
	X = cosmos.NewUint(100 * common.One)
	x = cosmos.NewUint(10 * common.One)
	Y = cosmos.NewUint(0 * common.One)

	// These calculations are verified by using the spreadsheet
	// https://docs.google.com/spreadsheets/d/1wJHYBRKBdw_WP7nUyVnkySPkOmPUNoiRGsEqgBVVXKU/edit#gid=0
	c.Check(calcAssetEmission(X, x, Y).Uint64(), Equals, uint64(0))
	c.Check(calcLiquidityFee(X, x, Y).Uint64(), Equals, uint64(0))
	c.Check(calcSwapSlip(X, x).Uint64(), Equals, uint64(909), Commentf("%d", calcSwapSlip(X, x).Uint64()))

	// side of the pool is zero
	X = cosmos.NewUint(0 * common.One)
	x = cosmos.NewUint(10 * common.One)
	Y = cosmos.NewUint(100 * common.One)

	// These calculations are verified by using the spreadsheet
	// https://docs.google.com/spreadsheets/d/1wJHYBRKBdw_WP7nUyVnkySPkOmPUNoiRGsEqgBVVXKU/edit#gid=0
	c.Check(calcAssetEmission(X, x, Y).Uint64(), Equals, uint64(0))
	c.Check(calcLiquidityFee(X, x, Y).Uint64(), Equals, uint64(100*common.One), Commentf("%d", calcLiquidityFee(X, x, Y).Uint64()))
	c.Check(calcSwapSlip(X, x).Uint64(), Equals, uint64(10000), Commentf("%d", calcSwapSlip(X, x).Uint64()))
}
