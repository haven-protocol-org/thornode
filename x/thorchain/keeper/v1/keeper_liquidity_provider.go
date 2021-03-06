package keeperv1

import (
	"fmt"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/x/thorchain/keeper/types"
)

func (k KVStore) setLiquidityProvider(ctx cosmos.Context, key string, record LiquidityProvider) {
	store := ctx.KVStore(k.storeKey)
	buf := k.cdc.MustMarshalBinaryBare(&record)
	if buf == nil {
		store.Delete([]byte(key))
	} else {
		store.Set([]byte(key), buf)
	}
}

func (k KVStore) getLiquidityProvider(ctx cosmos.Context, key string, record *LiquidityProvider) (bool, error) {
	store := ctx.KVStore(k.storeKey)
	if !store.Has([]byte(key)) {
		return false, nil
	}

	bz := store.Get([]byte(key))
	if err := k.cdc.UnmarshalBinaryBare(bz, record); err != nil {
		return true, dbError(ctx, fmt.Sprintf("Unmarshal kvstore: (%T) %s", record, key), err)
	}
	return true, nil
}

// GetLiquidityProviderIterator iterate liquidity providers
func (k KVStore) GetLiquidityProviderIterator(ctx cosmos.Context, asset common.Asset) cosmos.Iterator {
	key := k.GetKey(ctx, prefixLiquidityProvider, (&LiquidityProvider{Asset: asset}).Key())
	return k.getIterator(ctx, types.DbPrefix(key))
}

func (k KVStore) GetTotalSupply(ctx cosmos.Context, asset common.Asset) cosmos.Uint {
	supplier := k.coinKeeper.GetSupply(ctx)
	nativeDenom := asset.Native()
	for _, coin := range supplier.GetTotal() {
		if coin.Denom == nativeDenom {
			return cosmos.NewUint(coin.Amount.Uint64())
		}
	}
	return cosmos.ZeroUint()
}

// GetLiquidityProvider retrieve liquidity provider from the data store
func (k KVStore) GetLiquidityProvider(ctx cosmos.Context, asset common.Asset, addr common.Address) (LiquidityProvider, error) {
	record := LiquidityProvider{
		Asset:        asset,
		RuneAddress:  addr,
		Units:        cosmos.ZeroUint(),
		PendingRune:  cosmos.ZeroUint(),
		PendingAsset: cosmos.ZeroUint(),
	}
	if !addr.IsChain(common.RuneAsset().Chain) {
		record.AssetAddress = addr
		record.RuneAddress = common.NoAddress
	}

	_, err := k.getLiquidityProvider(ctx, k.GetKey(ctx, prefixLiquidityProvider, record.Key()), &record)
	if err != nil {
		return record, err
	}

	return record, nil
}

// SetLiquidityProvider save the liquidity provider to kv store
func (k KVStore) SetLiquidityProvider(ctx cosmos.Context, lp LiquidityProvider) {
	k.setLiquidityProvider(ctx, k.GetKey(ctx, prefixLiquidityProvider, lp.Key()), lp)
}

// RemoveLiquidityProvider remove the liquidity provider to kv store
func (k KVStore) RemoveLiquidityProvider(ctx cosmos.Context, lp LiquidityProvider) {
	k.del(ctx, k.GetKey(ctx, prefixLiquidityProvider, lp.Key()))
}
