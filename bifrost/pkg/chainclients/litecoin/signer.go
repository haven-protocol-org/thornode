package litecoin

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/hashicorp/go-multierror"
	"github.com/ltcsuite/ltcd/btcec"
	"github.com/ltcsuite/ltcd/btcjson"
	"github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/mempool"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/ltcutil"
	txscript "gitlab.com/thorchain/bifrost/ltcd-txscript"

	stypes "gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/bifrost/tss"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	mem "gitlab.com/thorchain/thornode/x/thorchain/memo"
)

const (
	// SatsPervBytes it should be enough , this one will only be used if signer can't find any previous UTXO , and fee info from local storage.
	SatsPervBytes = 25
	// MinUTXOConfirmation UTXO that has less confirmation then this will not be spent , unless it is yggdrasil
	MinUTXOConfirmation    = 1
	defaultMaxLTCFeeRate   = ltcutil.SatoshiPerBitcoin / 10
	maxUTXOsToSpend        = 15
	signUTXOBatchSize      = 10
	minSpendableUTXOAmount = 0.0001 // If UTXO is less than this , it will not observed , and will not spend it either
)

func getLTCPrivateKey(key cryptotypes.PrivKey) (*btcec.PrivateKey, error) {
	privateKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), key.Bytes())
	return privateKey, nil
}

func (c *Client) getChainCfg() *chaincfg.Params {
	cn := common.GetCurrentChainNetwork()
	switch cn {
	case common.MockNet:
		return &chaincfg.RegressionNetParams
	case common.TestNet:
		return &chaincfg.TestNet4Params
	case common.MainNet:
		return &chaincfg.MainNetParams
	}
	return nil
}

func (c *Client) getGasCoin(tx stypes.TxOutItem, vSize int64) common.Coin {
	gasRate := tx.GasRate
	// if the gas rate is zero , then try to get from last transaction fee
	if gasRate == 0 {
		fee, vBytes, err := c.blockMetaAccessor.GetTransactionFee()
		if err != nil {
			c.logger.Error().Err(err).Msg("fail to get previous transaction fee from local storage")
			return common.NewCoin(common.LTCAsset, cosmos.NewUint(uint64(vSize*gasRate)))
		}
		if fee != 0.0 && vSize != 0 {
			amt, err := ltcutil.NewAmount(fee)
			if err != nil {
				c.logger.Err(err).Msg("fail to convert amount from float64 to int64")
			} else {
				gasRate = int64(amt) / int64(vBytes) // sats per vbyte
			}
		}
	}
	// still empty , default to 25
	if gasRate == 0 {
		gasRate = int64(SatsPervBytes)
	}
	return common.NewCoin(common.LTCAsset, cosmos.NewUint(uint64(gasRate*vSize)))
}

// isYggdrasil - when the pubkey and node pubkey is the same that means it is signing from yggdrasil
func (c *Client) isYggdrasil(key common.PubKey) bool {
	return key.Equals(c.nodePubKey)
}

// getAllUtxos go through all the block meta in the local storage, it will spend all UTXOs in  block that might be evicted from local storage soon
// it also try to spend enough UTXOs that can add up to more than the given total
func (c *Client) getUtxoToSpend(pubKey common.PubKey, total float64) ([]btcjson.ListUnspentResult, error) {
	var result []btcjson.ListUnspentResult
	minConfirmation := 0
	// Yggdrasil vault is funded by asgard , which will only spend UTXO that is older than 10 blocks, so yggdrasil doesn't need
	// to do the same logic
	isYggdrasil := c.isYggdrasil(pubKey)
	utxos, err := c.getUTXOs(minConfirmation, MaximumConfirmation, pubKey)
	if err != nil {
		return nil, fmt.Errorf("fail to get UTXOs: %w", err)
	}
	// spend UTXO older to younger
	sort.SliceStable(utxos, func(i, j int) bool {
		if utxos[i].Confirmations > utxos[j].Confirmations {
			return true
		} else if utxos[i].Confirmations < utxos[j].Confirmations {
			return false
		}
		return utxos[i].TxID < utxos[j].TxID
	})
	var toSpend float64
	for _, item := range utxos {
		if item.Amount <= minSpendableUTXOAmount {
			continue
		}
		if isYggdrasil || item.Confirmations >= MinUTXOConfirmation || c.isSelfTransaction(item.TxID) {
			result = append(result, item)
			toSpend = toSpend + item.Amount
		}
		// in the scenario that there are too many unspent utxos available, make sure it doesn't spend too much
		// as too much UTXO will cause huge pressure on TSS, also make sure it will spend at least maxUTXOsToSpend
		// so the UTXOs will be consolidated
		if len(result) >= maxUTXOsToSpend && toSpend >= total {
			break
		}
	}
	return result, nil
}

// isSelfTransaction check the block meta to see whether the transactions is broadcast by ourselves
// if the transaction is broadcast by ourselves, then we should be able to spend the UTXO even it is still in mempool
// as such we could daisy chain the outbound transaction
func (c *Client) isSelfTransaction(txID string) bool {
	bms, err := c.blockMetaAccessor.GetBlockMetas()
	if err != nil {
		c.logger.Err(err).Msg("fail to get block metas")
		return false
	}
	for _, item := range bms {
		for _, tx := range item.SelfTransactions {
			if strings.EqualFold(tx, txID) {
				c.logger.Info().Msgf("%s is self transaction", txID)
				return true
			}
		}
	}
	return false
}

func (c *Client) getBlockHeight() (int64, error) {
	hash, err := c.client.GetBestBlockHash()
	if err != nil {
		return 0, fmt.Errorf("fail to get best block hash: %w", err)
	}
	blockInfo, err := c.client.GetBlockVerbose(hash)
	if err != nil {
		return 0, fmt.Errorf("fail to get the best block detail: %w", err)
	}

	return blockInfo.Height, nil
}

func (c *Client) getLTCPaymentAmount(tx stypes.TxOutItem) float64 {
	amtToPay := tx.Coins.GetCoin(common.LTCAsset).Amount.Uint64()
	amtToPayInLTC := ltcutil.Amount(int64(amtToPay)).ToBTC()
	if !tx.MaxGas.IsEmpty() {
		gasAmt := tx.MaxGas.ToCoins().GetCoin(common.LTCAsset).Amount
		amtToPayInLTC += ltcutil.Amount(int64(gasAmt.Uint64())).ToBTC()
	}
	return amtToPayInLTC
}

// getSourceScript retrieve pay to addr script from tx source
func (c *Client) getSourceScript(tx stypes.TxOutItem) ([]byte, error) {
	sourceAddr, err := tx.VaultPubKey.GetAddress(common.LTCChain)
	if err != nil {
		return nil, fmt.Errorf("fail to get source address: %w", err)
	}

	addr, err := ltcutil.DecodeAddress(sourceAddr.String(), c.getChainCfg())
	if err != nil {
		return nil, fmt.Errorf("fail to decode source address(%s): %w", sourceAddr.String(), err)
	}
	return txscript.PayToAddrScript(addr)
}

// estimateTxSize will create a temporary MsgTx, and use it to estimate the final tx size
// the value in the temporary MsgTx is not real
func (c *Client) estimateTxSize(tx stypes.TxOutItem, txes []btcjson.ListUnspentResult) (int64, error) {
	sourceScript, err := c.getSourceScript(tx)
	if err != nil {
		return 0, fmt.Errorf("fail to get source pay to address script: %w", err)
	}
	redeemTx := wire.NewMsgTx(wire.TxVersion)
	for _, item := range txes {
		txID, err := chainhash.NewHashFromStr(item.TxID)
		if err != nil {
			return 0, fmt.Errorf("fail to parse txID(%s): %w", item.TxID, err)
		}
		// double check that the utxo is still valid
		outputPoint := wire.NewOutPoint(txID, item.Vout)
		sourceTxIn := wire.NewTxIn(outputPoint, nil, nil)
		redeemTx.AddTxIn(sourceTxIn)
	}
	outputAddr, err := ltcutil.DecodeAddress(tx.ToAddress.String(), c.getChainCfg())
	if err != nil {
		return 0, fmt.Errorf("fail to decode next address: %w", err)
	}
	buf, err := txscript.PayToAddrScript(outputAddr)
	if err != nil {
		return 0, fmt.Errorf("fail to get pay to address script: %w", err)
	}

	redeemTxOut := wire.NewTxOut(int64(1024), buf)
	redeemTx.AddTxOut(redeemTxOut)
	redeemTx.AddTxOut(wire.NewTxOut(1024, sourceScript))

	// memo
	if len(tx.Memo) != 0 {
		nullDataScript, err := txscript.NullDataScript([]byte(tx.Memo))
		if err != nil {
			return 0, fmt.Errorf("fail to generate null data script: %w", err)
		}
		redeemTx.AddTxOut(wire.NewTxOut(0, nullDataScript))
	}
	// given the output in redeemTx has not been signed , so the estimated tx size will be smaller than the real size
	return mempool.GetTxVirtualSize(ltcutil.NewTx(redeemTx)), nil
}

// SignTx is going to generate the outbound transaction, and also sign it
func (c *Client) SignTx(tx stypes.TxOutItem, thorchainHeight int64) ([]byte, error) {
	if !tx.Chain.Equals(common.LTCChain) {
		return nil, errors.New("not LTC chain")
	}
	// when there is no coin , skip it
	if tx.Coins.IsEmpty() {
		return nil, nil
	}
	sourceScript, err := c.getSourceScript(tx)
	if err != nil {
		return nil, fmt.Errorf("fail to get source pay to address script: %w", err)
	}
	txes, err := c.getUtxoToSpend(tx.VaultPubKey, c.getLTCPaymentAmount(tx))
	if err != nil {
		return nil, fmt.Errorf("fail to get unspent UTXO")
	}
	redeemTx := wire.NewMsgTx(wire.TxVersion)
	totalAmt := float64(0)
	individualAmounts := make(map[chainhash.Hash]ltcutil.Amount, len(txes))
	for _, item := range txes {
		txID, err := chainhash.NewHashFromStr(item.TxID)
		if err != nil {
			return nil, fmt.Errorf("fail to parse txID(%s): %w", item.TxID, err)
		}
		// double check that the utxo is still valid
		outputPoint := wire.NewOutPoint(txID, item.Vout)
		sourceTxIn := wire.NewTxIn(outputPoint, nil, nil)
		redeemTx.AddTxIn(sourceTxIn)
		totalAmt += item.Amount
		amt, err := ltcutil.NewAmount(item.Amount)
		if err != nil {
			return nil, fmt.Errorf("fail to parse amount(%f): %w", item.Amount, err)
		}
		individualAmounts[*txID] = amt
	}

	outputAddr, err := ltcutil.DecodeAddress(tx.ToAddress.String(), c.getChainCfg())
	if err != nil {
		return nil, fmt.Errorf("fail to decode next address: %w", err)
	}
	buf, err := txscript.PayToAddrScript(outputAddr)
	if err != nil {
		return nil, fmt.Errorf("fail to get pay to address script: %w", err)
	}

	total, err := ltcutil.NewAmount(totalAmt)
	if err != nil {
		return nil, fmt.Errorf("fail to parse total amount(%f),err: %w", totalAmt, err)
	}
	coinToCustomer := tx.Coins.GetCoin(common.LTCAsset)
	totalSize, err := c.estimateTxSize(tx, txes)
	if err != nil {
		return nil, fmt.Errorf("fail to estimate tx size, err:%w", err)
	}

	// litecoind has a default rule max fee rate should less than 0.1 LTC / kb
	// the MaxGas coming from THORChain doesn't follow this rule , thus the MaxGas might be over the limit
	// as such , signer need to double check, if the MaxGas is over the limit , just pay the limit
	// the rest paid to customer to make sure the total doesn't change

	// maxFee in sats
	maxFeeSats := totalSize * defaultMaxLTCFeeRate / 1024
	gasCoin := c.getGasCoin(tx, totalSize)
	gasAmtSats := gasCoin.Amount.Uint64()

	// make sure the transaction fee is not more than 0.1 LTC / kb , otherwise it might reject the transaction
	if gasAmtSats > uint64(maxFeeSats) {
		diffSats := gasAmtSats - uint64(maxFeeSats) // in sats
		c.logger.Info().Msgf("gas amount: %d is larger than maximum fee: %d , diff: %d", gasAmtSats, uint64(maxFeeSats), diffSats)
		gasAmtSats = uint64(maxFeeSats)
	} else if gasAmtSats < c.minRelayFeeSats {
		diffStats := c.minRelayFeeSats - gasAmtSats
		c.logger.Info().Msgf("gas amount: %d is less than min relay fee: %d, diff remove from customer: %d", gasAmtSats, c.minRelayFeeSats, diffStats)
		gasAmtSats = c.minRelayFeeSats
	}

	// if the total gas spend is more than max gas , then we have to take away some from the amount pay to customer
	if !tx.MaxGas.IsEmpty() {
		maxGasCoin := tx.MaxGas.ToCoins().GetCoin(common.LTCAsset)
		if gasAmtSats > maxGasCoin.Amount.Uint64() {
			c.logger.Info().Msgf("max gas: %s, however estimated gas need %d", tx.MaxGas, gasAmtSats)
			gasAmtSats = maxGasCoin.Amount.Uint64()
		} else if gasAmtSats < maxGasCoin.Amount.Uint64() {
			// if the tx spend less gas then the estimated MaxGas , then the extra can be added to the coinToCustomer
			gap := maxGasCoin.Amount.Uint64() - gasAmtSats
			c.logger.Info().Msgf("max gas is: %s, however only: %d is required, gap: %d goes to customer", tx.MaxGas, gasAmtSats, gap)
			coinToCustomer.Amount = coinToCustomer.Amount.Add(cosmos.NewUint(gap))
		}
	} else {
		memo, err := mem.ParseMemo(tx.Memo)
		if err != nil {
			return nil, fmt.Errorf("fail to parse memo: %w", err)
		}
		if memo.GetType() == mem.TxYggdrasilReturn {
			gap := gasAmtSats
			c.logger.Info().Msgf("yggdrasil return asset , need gas: %d", gap)
			coinToCustomer.Amount = common.SafeSub(coinToCustomer.Amount, cosmos.NewUint(gap))
		}
	}
	gasAmt := ltcutil.Amount(gasAmtSats)
	if err := c.blockMetaAccessor.UpsertTransactionFee(gasAmt.ToBTC(), int32(totalSize)); err != nil {
		c.logger.Err(err).Msg("fail to save gas info to UTXO storage")
	}

	// pay to customer
	redeemTxOut := wire.NewTxOut(int64(coinToCustomer.Amount.Uint64()), buf)
	redeemTx.AddTxOut(redeemTxOut)

	// balance to ourselves
	// add output to pay the balance back ourselves
	balance := int64(total) - redeemTxOut.Value - int64(gasAmt)
	c.logger.Info().Msgf("total: %d, to customer: %d, gas: %d", int64(total), redeemTxOut.Value, int64(gasAmt))
	if balance < 0 {
		return nil, fmt.Errorf("not enough balance to pay customer: %d", balance)
	}
	if balance > 0 {
		c.logger.Info().Msgf("send %d back to self", balance)
		redeemTx.AddTxOut(wire.NewTxOut(balance, sourceScript))
	}

	// memo
	if len(tx.Memo) != 0 {
		nullDataScript, err := txscript.NullDataScript([]byte(tx.Memo))
		if err != nil {
			return nil, fmt.Errorf("fail to generate null data script: %w", err)
		}
		redeemTx.AddTxOut(wire.NewTxOut(0, nullDataScript))
	}
	wg := &sync.WaitGroup{}
	var utxoErr error
	for idx, txIn := range redeemTx.TxIn {
		outputAmount := int64(individualAmounts[txIn.PreviousOutPoint.Hash])
		wg.Add(1)
		go func(i int, amount int64) {
			defer wg.Done()
			if err := c.signUTXO(redeemTx, tx, amount, sourceScript, i, thorchainHeight); err != nil {
				if nil == utxoErr {
					utxoErr = err
				} else {
					utxoErr = multierror.Append(utxoErr, err)
				}
			}
		}(idx, outputAmount)
		if (idx+1)%signUTXOBatchSize == 0 {
			// Let's wait until the batch is finished first
			wg.Wait()
		}
		// if the first batch already error out , bail
		if utxoErr != nil {
			break
		}
	}
	wg.Wait()
	if utxoErr != nil {
		return nil, fmt.Errorf("fail to sign the message: %w", utxoErr)
	}
	finalSize := redeemTx.SerializeSize()
	finalVBytes := mempool.GetTxVirtualSize(ltcutil.NewTx(redeemTx))
	c.logger.Info().Msgf("estimate:%d, final size: %d, final vbyte: %d", totalSize, finalSize, finalVBytes)
	var signedTx bytes.Buffer
	if err := redeemTx.Serialize(&signedTx); err != nil {
		return nil, fmt.Errorf("fail to serialize tx to bytes: %w", err)
	}

	return signedTx.Bytes(), nil
}

func (c *Client) signUTXO(redeemTx *wire.MsgTx, tx stypes.TxOutItem, amount int64, sourceScript []byte, idx int, thorchainHeight int64) error {
	sigHashes := txscript.NewTxSigHashes(redeemTx)
	sig := c.ksWrapper.GetSignable(tx.VaultPubKey)
	witness, err := txscript.WitnessSignature(redeemTx, sigHashes, idx, amount, sourceScript, txscript.SigHashAll, sig, true)
	if err != nil {
		var keysignError tss.KeysignError
		if errors.As(err, &keysignError) {
			if len(keysignError.Blame.BlameNodes) == 0 {
				// TSS doesn't know which node to blame
				return fmt.Errorf("fail to sign UTXO: %w", err)
			}

			// key sign error forward the keysign blame to thorchain
			txID, err := c.bridge.PostKeysignFailure(keysignError.Blame, thorchainHeight, tx.Memo, tx.Coins, tx.VaultPubKey)
			if err != nil {
				c.logger.Error().Err(err).Msg("fail to post keysign failure to thorchain")
				return fmt.Errorf("fail to post keysign failure to THORChain: %w", err)
			}
			c.logger.Info().Str("tx_id", txID.String()).Msgf("post keysign failure to thorchain")
		}
		return fmt.Errorf("fail to get witness: %w", err)
	}

	redeemTx.TxIn[idx].Witness = witness
	flag := txscript.StandardVerifyFlags
	engine, err := txscript.NewEngine(sourceScript, redeemTx, idx, flag, nil, nil, amount)
	if err != nil {
		return fmt.Errorf("fail to create engine: %w", err)
	}
	if err := engine.Execute(); err != nil {
		return fmt.Errorf("fail to execute the script: %w", err)
	}
	return nil
}

// BroadcastTx will broadcast the given payload to LTC chain
func (c *Client) BroadcastTx(txOut stypes.TxOutItem, payload []byte) (string, error) {
	redeemTx := wire.NewMsgTx(wire.TxVersion)
	buf := bytes.NewBuffer(payload)
	if err := redeemTx.Deserialize(buf); err != nil {
		return "", fmt.Errorf("fail to deserialize payload: %w", err)
	}

	height, err := c.getBlockHeight()
	if err != nil {
		return "", fmt.Errorf("fail to get block height: %w", err)
	}
	bm, err := c.blockMetaAccessor.GetBlockMeta(height)
	if err != nil {
		c.logger.Err(err).Msgf("fail to get blockmeta for heigth: %d", height)
	}
	if bm == nil {
		bm = NewBlockMeta("", height, "")
	}
	defer func() {
		if err := c.blockMetaAccessor.SaveBlockMeta(height, bm); err != nil {
			c.logger.Err(err).Msg("fail to save block metadata")
		}
	}()
	// broadcast tx
	txHash, err := c.client.SendRawTransaction(redeemTx, true)
	if txHash != nil {
		bm.AddSelfTransaction(txHash.String())
	}
	if err != nil {
		if rpcErr, ok := err.(*btcjson.RPCError); ok && rpcErr.Code == btcjson.ErrRPCTxAlreadyInChain {
			// this means the tx had been broadcast to chain, it must be another signer finished quicker then us
			return redeemTx.TxHash().String(), nil
		}

		return "", fmt.Errorf("fail to broadcast transaction to chain: %w", err)
	}
	// save tx id to block meta in case we need to errata later
	c.logger.Info().Str("hash", txHash.String()).Msg("broadcast to LTC chain successfully")
	return txHash.String(), nil
}
