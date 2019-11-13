package thorchain

import (
	"sort"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"gitlab.com/thorchain/bepswap/thornode/common"
)

// TODO: make this admin configs instead of hard coded
var singleTransactionFee uint64 = 37500

// var batchTransactionFee uint64 = 30000

// TxOutSetter define a method that is required to be used in TxOutStore
// We need this interface thus we could test the refund logic accordingly
type TxOutSetter interface {
	SetTxOut(sdk.Context, *TxOut)
}

// TxOutStore is going to manage all the outgoing tx
type TxOutStore struct {
	txOutSetter TxOutSetter
	blockOut    *TxOut
	poolAddrMgr *PoolAddressManager
}

// NewTxOutStore will create a new instance of TxOutStore.
func NewTxOutStore(txOutSetter TxOutSetter, poolAddrMgr *PoolAddressManager) *TxOutStore {
	return &TxOutStore{
		txOutSetter: txOutSetter,
		poolAddrMgr: poolAddrMgr,
	}
}

// NewBlock create a new block
func (tos *TxOutStore) NewBlock(height uint64) {
	tos.blockOut = NewTxOut(height)
}

// CommitBlock we write the block into key value store , thus we could send to signer later.
func (tos *TxOutStore) CommitBlock(ctx sdk.Context) {
	// if we don't have anything in the array, we don't need to save
	if len(tos.blockOut.TxArray) == 0 {
		return
	}

	// write the tos to keeper
	tos.txOutSetter.SetTxOut(ctx, tos.blockOut)
}

func (tos *TxOutStore) GetOutboundItems() []*TxOutItem {
	return tos.blockOut.TxArray
}

// AddTxOutItem add an item to internal structure
func (tos *TxOutStore) AddTxOutItem(ctx sdk.Context, keeper Keeper, toi *TxOutItem, deductFee, asgard bool) {
	// Default the memo to the standard outbound memo
	if toi.Memo == "" {
		toi.Memo = NewOutboundMemo(toi.InHash).String()
	}

	if deductFee {
		switch toi.Coin.Asset.Chain {
		case common.BNBChain:
			tos.ApplyBNBFees(ctx, keeper, toi)
		default:
			// No gas policy for this chain (yet)
		}
	}

	// If we don't have a pool already selected to send from, discover one.
	if toi.PoolAddress.IsEmpty() {
		if !asgard {
			// When deciding which Yggdrasil pool will send out our tx out, we
			// should consider which ones observed the inbound request tx, as
			// yggdrasil pools can go offline. Here we get the voter record and
			// only consider Yggdrasils where their observed saw the "correct"
			// tx.

			activeNodeAccounts, err := keeper.ListActiveNodeAccounts(ctx)
			if len(activeNodeAccounts) > 0 && err == nil {
				voter := keeper.GetTxInVoter(ctx, toi.InHash)
				tx := voter.GetTx(activeNodeAccounts)

				// collect yggdrasil pools
				var yggs Yggdrasils
				iterator := keeper.GetYggdrasilIterator(ctx)
				defer iterator.Close()
				for ; iterator.Valid(); iterator.Next() {
					var ygg Yggdrasil
					keeper.cdc.MustUnmarshalBinaryBare(iterator.Value(), &ygg)
					// if we are already sending assets from this ygg pool, deduct
					// them.
					addr, _ := ygg.PubKey.GetThorAddress()
					if tx.HasSigned(addr) {
						for _, tx := range tos.blockOut.TxArray {
							if tx.PoolAddress.Equals(ygg.PubKey) {
								for i, yggcoin := range ygg.Coins {
									if yggcoin.Asset.Equals(tx.Coin.Asset) {
										ygg.Coins[i].Amount = ygg.Coins[i].Amount.Sub(tx.Coin.Amount)
									}
								}
							}
						}
						yggs = append(yggs, ygg)
					}
				}

				// use the ygg pool with the highest quantity of our coin
				sort.Slice(yggs[:], func(i, j int) bool {
					return yggs[i].GetCoin(toi.Coin.Asset).Amount.GT(
						yggs[j].GetCoin(toi.Coin.Asset).Amount,
					)
				})

				// if none of our Yggdrasil pools have enough funds to fulfil
				// the order, fallback to our Asguard pool
				if len(yggs) > 0 {
					if toi.Coin.Amount.LT(yggs[0].GetCoin(toi.Coin.Asset).Amount) {
						toi.PoolAddress = yggs[0].PubKey
					}
				}

			}
		}

	}

	if toi.PoolAddress.IsEmpty() {
		toi.PoolAddress = tos.poolAddrMgr.GetCurrentPoolAddresses().Current.GetByChain(toi.Chain).PubKey
	}

	// Ensure we are not sending from and to the same address
	// we check for a
	fromAddr, err := toi.PoolAddress.GetAddress(toi.Chain)
	if err != nil || fromAddr.IsEmpty() || toi.ToAddress.Equals(fromAddr) {
		return
	}

	if toi.Coin.IsEmpty() {
		return
	}

	// increment out number of out tx for this in tx
	voter := keeper.GetTxInVoter(ctx, toi.InHash)
	voter.NumOuts += 1
	keeper.SetTxInVoter(ctx, voter)

	// add tx to block out
	tos.addToBlockOut(toi)
}

func (tos *TxOutStore) ApplyBNBFees(ctx sdk.Context, keeper Keeper, toi *TxOutItem) {
	gas := singleTransactionFee

	if toi.Coin.Asset.IsBNB() {
		if toi.Coin.Amount.LTE(sdk.NewUint(gas)) {
			toi.Coin.Amount = sdk.ZeroUint()
		} else {
			toi.Coin.Amount = toi.Coin.Amount.SubUint64(gas)
		}

		// no need to update the bnb pool with new amounts.

	} else if toi.Coin.Asset.IsRune() {
		bnbPool := keeper.GetPool(ctx, common.BNBAsset)

		if bnbPool.BalanceAsset.LT(sdk.NewUint(gas)) {
			// not enough gas to be able to send coins
			return
		}

		var runeAmt uint64
		runeAmt = uint64(float64(bnbPool.BalanceRune.Uint64()) / (float64(bnbPool.BalanceAsset.Uint64()) / float64(gas)))

		if toi.Coin.Amount.LTE(sdk.NewUint(runeAmt)) {
			toi.Coin.Amount = sdk.ZeroUint()
		} else {
			toi.Coin.Amount = toi.Coin.Amount.SubUint64(runeAmt)
		}

		// add the rune to the bnb pool that we are subtracting from
		// the refund
		bnbPool.BalanceRune = bnbPool.BalanceRune.AddUint64(runeAmt)
		bnbPool.BalanceAsset = bnbPool.BalanceAsset.SubUint64(gas)
		keeper.SetPool(ctx, bnbPool)

	} else {
		bnbPool := keeper.GetPool(ctx, common.BNBAsset)
		assetPool := keeper.GetPool(ctx, toi.Coin.Asset)

		var runeAmt, assetAmt uint64
		runeAmt = uint64(float64(bnbPool.BalanceRune.Uint64()) / (float64(bnbPool.BalanceAsset.Uint64()) / float64(gas)))
		assetAmt = uint64(float64(assetPool.BalanceRune.Uint64()) / (float64(assetPool.BalanceAsset.Uint64()) / float64(runeAmt)))

		if toi.Coin.Amount.LTE(sdk.NewUint(assetAmt)) {
			toi.Coin.Amount = sdk.ZeroUint()
		} else {
			toi.Coin.Amount = toi.Coin.Amount.SubUint64(assetAmt)
		}

		// add the rune to the bnb pool that we are subtracting from
		// the refund
		bnbPool.BalanceRune = bnbPool.BalanceRune.AddUint64(runeAmt)
		bnbPool.BalanceAsset = bnbPool.BalanceAsset.SubUint64(gas)
		keeper.SetPool(ctx, bnbPool)
		assetPool.BalanceRune = assetPool.BalanceRune.SubUint64(runeAmt)
		assetPool.BalanceAsset = assetPool.BalanceAsset.AddUint64(assetAmt)
		keeper.SetPool(ctx, assetPool)
	}
}

func (tos *TxOutStore) addToBlockOut(toi *TxOutItem) {
	toi.SeqNo = tos.getSeqNo(toi.Chain)
	tos.blockOut.TxArray = append(tos.blockOut.TxArray, toi)
}

func (tos *TxOutStore) getSeqNo(chain common.Chain) uint64 {
	// need to get the sequence no
	currentChainPoolAddr := tos.poolAddrMgr.currentPoolAddresses.Current.GetByChain(chain)
	if nil != currentChainPoolAddr {
		return currentChainPoolAddr.GetSeqNo()
	}
	if nil != tos.poolAddrMgr.currentPoolAddresses.Previous {
		previousChainPoolAddr := tos.poolAddrMgr.currentPoolAddresses.Previous.GetByChain(chain)
		if nil != previousChainPoolAddr {
			return previousChainPoolAddr.GetSeqNo()
		}
	}
	if nil != tos.poolAddrMgr.currentPoolAddresses.Next {
		nextChainPoolAddr := tos.poolAddrMgr.currentPoolAddresses.Next.GetByChain(chain)
		if nil != nextChainPoolAddr {
			return nextChainPoolAddr.GetSeqNo()
		}
	}
	return uint64(0)
}
