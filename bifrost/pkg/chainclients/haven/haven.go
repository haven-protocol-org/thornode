package haven

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	btypes "gitlab.com/thorchain/thornode/bifrost/blockscanner/types"
	"gitlab.com/thorchain/thornode/bifrost/pubkeymanager"
	"gitlab.com/thorchain/tss/monero-wallet-rpc/wallet"

	tssp "github.com/akildemir/moneroTss/tss"
	"github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/haven-protocol-org/monero-go-utils/crypto"
	"github.com/powerman/rpc-codec/jsonrpc2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/thornode/bifrost/blockscanner"
	"gitlab.com/thorchain/thornode/bifrost/config"
	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	"gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	stypes "gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/bifrost/tss"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	mem "gitlab.com/thorchain/thornode/x/thorchain/memo"
)

// Client observes bitcoin chain and allows to sign and broadcast tx
type Client struct {
	logger             zerolog.Logger
	cfg                config.ChainConfiguration
	chain              common.Chain
	pubSpendKey        [32]byte
	pubViewKey         [32]byte
	walletAddr         common.Address
	processedMemPool   map[string]bool
	memPoolLock        *sync.Mutex
	lastMemPoolScan    time.Time
	currentBlockHeight int64
	blockScanner       *blockscanner.BlockScanner
	blockMetaAccessor  BlockMetaAccessor
	ksWrapper          *KeySignWrapper
	bridge             *thorclient.ThorchainBridge
	globalErrataQueue  chan<- types.ErrataBlock
	asgardAddresses    []common.Address
	nodePubKey         common.PubKey
	pkm                pubkeymanager.PubKeyValidator
	lastSignedTxHash   string
	tssKm              tss.ThorchainKeyManager
}

type TxVout struct {
	Address string
	Amount  uint64
	Asset   string
}

// BlockCacheSize the number of block meta that get store in storage.
const BlockCacheSize = 100

// NewClient generates a new Client
func NewClient(thorKeys *thorclient.Keys, cfg config.ChainConfiguration, server *tssp.TssServer, bridge *thorclient.ThorchainBridge, pkm pubkeymanager.PubKeyValidator, m *metrics.Metrics) (*Client, error) {

	// update the ip address for daemon and wallet-rpc
	// TODO: this is a temp solution for test
	DaemonHost = cfg.RPCHost
	WalletRPCHost = cfg.WalletRPCHost

	tssKm, err := tss.NewKeySignMn(server, bridge, common.XHVChain)
	if err != nil {
		return nil, fmt.Errorf("fail to create tss signer: %w", err)
	}

	// Get thor keys
	thorPriveKey, err := thorKeys.GetPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("fail to get THORChain private key: %w", err)
	}
	temp, err := codec.ToTmPubKeyInterface(thorPriveKey.PubKey())
	if err != nil {
		return nil, fmt.Errorf("fail to get tm pub key: %w", err)
	}
	thorPubkey, err := common.NewPubKeyFromCrypto(temp)
	if err != nil {
		return nil, fmt.Errorf("fail to get the node pubkey: %w", err)
	}

	// generate private keys for local haven wallet
	havenPrivViewKey, havenPrivSpendKey := getHavenPrivateKey(thorPriveKey)

	// try to generate a haven wallet
	pubSpenKey, pubViewKey, walletAddr, err := generateHavenWallet(&havenPrivSpendKey, &havenPrivViewKey, "havenBifrost", "passwd")
	if err != nil {
		return nil, fmt.Errorf("Fail to create a haven wallet: %+v", err)
	}

	// make a sign wrapper
	ksWrapper, err := NewKeySignWrapper(havenPrivViewKey, havenPrivSpendKey, thorPubkey, tssKm)
	if err != nil {
		return nil, fmt.Errorf("fail to create keysign wrapper: %w", err)
	}

	c := &Client{
		logger:           log.Logger.With().Str("module", "haven").Logger(),
		cfg:              cfg,
		chain:            cfg.ChainID,
		pubSpendKey:      pubSpenKey,
		pubViewKey:       pubViewKey,
		ksWrapper:        ksWrapper,
		bridge:           bridge,
		pkm:              pkm,
		nodePubKey:       thorPubkey,
		walletAddr:       walletAddr,
		memPoolLock:      &sync.Mutex{},
		tssKm:            tssKm,
		processedMemPool: make(map[string]bool),
	}

	var path string // if not set later, will in memory storage
	if len(c.cfg.BlockScanner.DBPath) > 0 {
		path = fmt.Sprintf("%s/%s", c.cfg.BlockScanner.DBPath, c.cfg.BlockScanner.ChainID)
	}
	storage, err := blockscanner.NewBlockScannerStorage(path)
	if err != nil {
		return c, fmt.Errorf("fail to create blockscanner storage: %w", err)
	}

	c.blockScanner, err = blockscanner.NewBlockScanner(c.cfg.BlockScanner, storage, m, bridge, c)
	if err != nil {
		return c, fmt.Errorf("fail to create block scanner: %w", err)
	}

	dbAccessor, err := NewLevelDBBlockMetaAccessor(storage.GetInternalDb())
	if err != nil {
		return c, fmt.Errorf("fail to create utxo accessor: %w", err)
	}
	c.blockMetaAccessor = dbAccessor

	c.logger.Info().Msgf("local vault Haven address %s", c.walletAddr.String())
	c.logger.Info().Msgf("Haven Daemon IP address %s", DaemonHost)
	c.logger.Info().Msgf("Haven Wallet-Rpc IP address %s", WalletRPCHost)
	return c, nil
}

// Start starts the block scanner
func (c *Client) Start(globalTxsQueue chan types.TxIn, globalErrataQueue chan types.ErrataBlock) {
	c.blockScanner.Start(globalTxsQueue)
	c.globalErrataQueue = globalErrataQueue
}

// Stop stops the block scanner
func (c *Client) Stop() {
	c.blockScanner.Stop()
}

// GetConfig - get the chain configuration
func (c *Client) GetConfig() config.ChainConfiguration {
	return c.cfg
}

// GetChain returns haven Chain
func (c *Client) GetChain() common.Chain {
	return common.XHVChain
}

// GetHeight returns current block height
func (c *Client) GetHeight() (int64, error) {
	height, err := GetHeight()
	if err != nil {
		return 0, fmt.Errorf("Failed to get height: %+v", err)
	}
	return height, nil
}

// GetAddress return current local haven vault address
func (c *Client) GetAddress(poolPubKey common.PubKey) string {
	return c.walletAddr.String()
}

// GetAccountByAddress return empty account for now
func (c *Client) GetAccountByAddress(address string) (common.Account, error) {
	return common.Account{}, nil
}

// GetAccount returns account with balance for an address
func (c *Client) GetAccount(pkey common.PubKey) (common.Account, error) {

	// make a new account instance to return in case of an error
	acct := common.Account{}

	// get all block metas
	blockMetas, err := c.blockMetaAccessor.GetBlockMetas()
	if err != nil {
		return acct, fmt.Errorf("fail to get block meta: %w", err)
	}

	// calculate total spendable amount in all blocks
	total := 0.0
	for _, item := range blockMetas {
		for _, utxo := range item.GetUTXOs(pkey) {
			total += utxo.Value
		}
	}
	total = total * 1000000000000 // 12 zeros

	// return a new Account with the total amount spendable.
	return common.NewAccount(0, 0,
		common.Coins{
			common.NewCoin(common.BTCAsset, cosmos.NewUint(uint64(total))),
		}, false), nil
}

func (c *Client) getCoinbaseValue(blockHeight int64) (int64, error) {

	// define types to read the miner tx into
	type minerTX struct {
		Vout []map[string]interface{}
	}
	type bJson struct {
		Miner_Tx minerTX
	}

	// get block
	block, err := GetBlock(blockHeight)
	if err != (jsonrpc2.Error{}) {
		return 0, fmt.Errorf("fail to get block verbose tx: %s", err.Message)
	}

	// parse the returned resutl
	var result bJson
	err2 := json.Unmarshal([]byte(block.Json), &result)
	if err2 != nil {
		return 0, fmt.Errorf("getCoinbaseValue() Unmarshaling Miner Tx Error: %+v\n", err2)
	}

	amount := int64(31058480894586)
	return amount, nil
}

// getBlockRequiredConfirmation find out how many confirmation the given txIn need to have before it can be send to THORChain
func (c *Client) getBlockRequiredConfirmation(txIn types.TxIn, height int64) (int64, error) {
	totalTxValue := txIn.GetTotalTransactionValue(common.XHVAsset, c.asgardAddresses)
	totalFeeAndSubsidy, err := c.getCoinbaseValue(height)
	if err != nil {
		return totalFeeAndSubsidy, fmt.Errorf("fail to get coinbase value: %w", err)
	}
	confirm := totalTxValue.MulUint64(2).QuoUint64(uint64(totalFeeAndSubsidy)).Uint64()
	c.logger.Info().Msgf("totalTxValue:%s,total fee and Subsidy:%d,confirmation:%d", totalTxValue, totalFeeAndSubsidy, confirm)
	return int64(confirm), nil
}

// GetConfirmationCount return the number of blocks the tx need to wait before processing in THORChain
func (c *Client) GetConfirmationCount(txIn types.TxIn) int64 {
	if len(txIn.TxArray) == 0 {
		return 0
	}
	// MemPool items doesn't need confirmation
	if txIn.MemPool {
		return 0
	}
	blockHeight := txIn.TxArray[0].BlockHeight
	confirm, err := c.getBlockRequiredConfirmation(txIn, blockHeight)
	// c.logger.Info().Msgf("confirmation required: %d", confirm)
	if err != nil {
		c.logger.Err(err).Msg("fail to get block confirmation ")
		return 0
	}
	return confirm
}

// ConfirmationCountReady will be called by observer before send the txIn to thorchain
// confirmation counting is on block level
func (c *Client) ConfirmationCountReady(txIn types.TxIn) bool {
	if len(txIn.TxArray) == 0 {
		return true
	}
	// MemPool items doesn't need confirmation
	if txIn.MemPool {
		return true
	}
	blockHeight := txIn.TxArray[0].BlockHeight
	confirm := txIn.ConfirmationRequired
	c.logger.Info().Msgf("confirmation required: %d", confirm)
	// every tx in txIn already have at least 1 confirmation
	return (c.currentBlockHeight - blockHeight) >= confirm
}

// OnObservedTxIn gets called from observer when we have a valid observation
// For bitcoin chain client we want to save the utxo we can spend later to sign
func (c *Client) OnObservedTxIn(txIn types.TxInItem, blockHeight int64) {

	// get the txItem value
	value := float64(txIn.Coins.GetCoin(common.XHVAsset).Amount.Uint64()) / 1000000000000

	// get the block meta for this height
	blockMeta, err := c.blockMetaAccessor.GetBlockMeta(blockHeight)
	if nil != err {
		c.logger.Err(err).Msgf("fail to get block meta on block height(%d)", blockHeight)
	}
	if nil == blockMeta {
		c.logger.Error().Msgf("can't get block meta for height: %d", blockHeight)
		return
	}

	// create a new unspent transaction output and save to the block it belongs to.
	utxo := NewUnspentTransactionOutput(txIn.Tx, 0, value, blockHeight, txIn.ObservedVaultPubKey)
	blockMeta.AddUTXO(utxo)
	if err := c.blockMetaAccessor.SaveBlockMeta(blockHeight, blockMeta); err != nil {
		c.logger.Err(err).Msgf("fail to save block meta to storage,block height(%d)", blockHeight)
	}
}

// FetchTxs retrieves txs for a block height
func (c *Client) FetchTxs(height int64) (types.TxIn, error) {

	block, err := GetBlock(height)
	if err != (jsonrpc2.Error{}) {
		if err.Code == -2 {
			return types.TxIn{}, btypes.UnavailableBlock
		}
		return types.TxIn{}, fmt.Errorf("fail to get block: %s", err.Message)
	}
	c.currentBlockHeight = height

	// Check for reorg
	if err := c.processReorg(block); err != nil {
		c.logger.Err(err).Msg("fail to process bitcoin re-org")
	}

	// update block meta
	blockMeta, err2 := c.blockMetaAccessor.GetBlockMeta(block.Block_Header.Height)
	if err2 != nil {
		return types.TxIn{}, fmt.Errorf("fail to get block meta from storage: %w", err2)
	}
	if blockMeta == nil {
		blockMeta = NewBlockMeta(block.Block_Header.Prev_Hash, block.Block_Header.Height, block.Block_Header.Hash)
	} else {
		blockMeta.PreviousHash = block.Block_Header.Prev_Hash
		blockMeta.BlockHash = block.Block_Header.Hash
	}
	if err2 := c.blockMetaAccessor.SaveBlockMeta(block.Block_Header.Height, blockMeta); err2 != nil {
		return types.TxIn{}, fmt.Errorf("fail to save block meta into storage: %w", err2)
	}

	// update prune block meta
	pruneHeight := height - BlockCacheSize
	if pruneHeight > 0 {
		defer func() {
			if err2 := c.blockMetaAccessor.PruneBlockMeta(pruneHeight); err2 != nil {
				c.logger.Err(err2).Msgf("fail to prune block meta, height(%d)", pruneHeight)
			}
		}()
	}

	// get txs as txInItems
	txs, err2 := c.extractTxs(block)
	if err2 != nil {
		return types.TxIn{}, fmt.Errorf("fail to extract txs from block: %w", err2)
	}

	// send thorchain network fee
	if err2 := c.sendNetworkFee(height); err2 != nil {
		c.logger.Err(err2).Msg("fail to send network fee")
	}

	return txs, nil
}

func (c *Client) sendNetworkFee(height int64) error {

	// TODO: an endpoint to get the AverageTxSize and AverageFeeRate
	// result, err := c.client.GetBlockStats(height, nil)
	// if err != nil {
	// 	return fmt.Errorf("fail to get block stats")
	// }
	// // fee rate and tx size should not be 0
	// if result.AverageFeeRate == 0 || result.AverageTxSize == 0 {
	// 	return nil
	// }

	txid, err := c.bridge.PostNetworkFee(height, common.XHVChain, 2, uint64(155600))
	if err != nil {
		return fmt.Errorf("fail to post network fee to thornode: %w", err)
	}
	c.logger.Debug().Str("txid", txid.String()).Msg("send network fee to THORNode successfully")
	return nil
}

func (c *Client) processReorg(block Block) error {
	previousHeight := block.Block_Header.Height - 1
	prevBlockMeta, err := c.blockMetaAccessor.GetBlockMeta(previousHeight)
	if err != nil {
		return fmt.Errorf("fail to get block meta of height(%d) : %w", previousHeight, err)
	}
	if prevBlockMeta == nil {
		return nil
	}
	// the block's previous hash need to be the same as the block hash chain client recorded in block meta
	// blockMetas[PreviousHeight].BlockHash == Block.PreviousHash
	if strings.EqualFold(prevBlockMeta.BlockHash, block.Block_Header.Prev_Hash) {
		return nil
	}

	c.logger.Info().Msgf("re-org detected, current block height:%d ,previous block hash is : %s , however block meta at height: %d, block hash is %s", block.Block_Header.Height, block.Block_Header.Prev_Hash, prevBlockMeta.Height, prevBlockMeta.BlockHash)
	return c.reConfirmTx()
}

// reConfirmTx will be kicked off only when chain client detected a re-org on bitcoin chain
// it will read through all the block meta data from local storage , and go through all the UTXOes.
// For each UTXO , it will send a RPC request to bitcoin chain , double check whether the TX exist or not
// if the tx still exist , then it is all good, if a transaction previous we detected , however doesn't exist anymore , that means
// the transaction had been removed from chain,  chain client should report to thorchain
func (c *Client) reConfirmTx() error {
	blockMetas, err := c.blockMetaAccessor.GetBlockMetas()
	if err != nil {
		return fmt.Errorf("fail to get block metas from local storage: %w", err)
	}

	for _, blockMeta := range blockMetas {
		var errataTxs []types.ErrataTx
		for _, utxo := range blockMeta.UnspentTransactionOutputs {
			txID := utxo.TxID
			if c.confirmTx(utxo.TxID) {
				c.logger.Info().Msgf("block height: %d, tx: %s still exist", blockMeta.Height, txID)
				continue
			}
			// this means the tx doesn't exist in chain ,thus should errata it
			errataTxs = append(errataTxs, types.ErrataTx{
				TxID:  common.TxID(txID),
				Chain: common.XHVChain,
			})
			// remove the UTXO from block meta , so signer will not spend it
			blockMeta.RemoveUTXO(utxo.GetKey())
		}
		if len(errataTxs) == 0 {
			continue
		}
		c.globalErrataQueue <- types.ErrataBlock{
			Height: blockMeta.Height,
			Txs:    errataTxs,
		}
		// Let's get the block again to fix the block hash
		r, err := GetBlock(blockMeta.Height)
		if err != (jsonrpc2.Error{}) {
			c.logger.Err(fmt.Errorf(err.Message)).Msgf("fail to get block verbose tx result: %d", blockMeta.Height)
		}
		blockMeta.PreviousHash = r.Block_Header.Prev_Hash
		blockMeta.BlockHash = r.Block_Header.Hash
		if err := c.blockMetaAccessor.SaveBlockMeta(blockMeta.Height, blockMeta); err != nil {
			c.logger.Err(err).Msgf("fail to save block meta of height: %d ", blockMeta.Height)
		}
	}
	return nil
}

// confirmTx check a tx is valid on chain post reorg
func (c *Client) confirmTx(txHash string) bool {

	// first check if tx is in mempool, just signed it for example
	// if no error it means its valid mempool tx and move on
	poolTxs, err := GetPoolTxs()
	if err != nil {
		c.logger.Err(err).Msgf("fail to get pool txs result: %w", err)
		return false
	}

	// check if the tx is still in the pool. If it is, that means it is a valid tx.
	for _, tx := range poolTxs {
		if tx == txHash {
			return true
		}
	}

	// then get raw tx and check if it has confirmations or not
	// if no confirmation and not in mempool then invalid
	var txHashes = make([]string, 0)
	txHashes = append(txHashes, txHash)
	txs, err := GetTxes(txHashes)
	if err != nil {
		c.logger.Err(err).Msgf("Error Getting Tx: %s", txHash)
		return false
	}

	// check if the tx has confirmations
	currentHeight, err := GetHeight()
	if currentHeight > txs[0].Block_Height {
		return true
	}

	return false
}

// extractTxs extracts txs from a block to type TxIn
func (c *Client) extractTxs(block Block) (types.TxIn, error) {

	// prepare the TxIn
	txIn := types.TxIn{
		Chain: c.GetChain(),
	}

	// get txs from daemon
	txs, err := GetTxes(block.Tx_Hashes)
	if err != nil {
		return txIn, fmt.Errorf("Failed to get txs from daemon: %w", err)
	}

	// populate txItems
	var txItems []types.TxInItem
	for _, tx := range txs {

		c.logger.Info().Msgf("Checkin Tx: %s", tx.Hash)

		// remove from pool cache
		c.removeFromMemPoolCache(tx.Hash)

		// get txInItem
		txInItem, err := c.getTxIn(&tx, block.Block_Header.Height)
		if err != nil {
			c.logger.Err(err).Msg("fail to get TxInItem")
			continue
		}
		if txInItem.IsEmpty() {
			c.logger.Info().Msgf("Ignoring Tx with empty TxInItem: %s", tx.Hash)
			continue
		}

		// append to txItems
		txItems = append(txItems, txInItem)
	}
	txIn.TxArray = txItems
	txIn.Count = strconv.Itoa(len(txItems))
	return txIn, nil
}

func (c *Client) getTxIn(tx *RawTx, height int64) (types.TxInItem, error) {

	// parse tx extra
	parsedTxExtra, err := c.parseTxExtra(tx.Extra)
	if err != nil {
		return types.TxInItem{}, fmt.Errorf("Error Parsing Tx Extra: %w\n", err)
	}

	// get tx public key
	var txPubKey [32]byte
	if len(parsedTxExtra[1]) != 1 {
		c.logger.Info().Msg("Ignoring a Tx wit more than one tx key")
		return types.TxInItem{}, nil
	}
	copy(txPubKey[:], parsedTxExtra[1][0][0:32])

	// get the output
	output, err := c.getOutput(tx, &txPubKey)
	if err != nil {
		return types.TxInItem{}, fmt.Errorf("Error Decrypting Tx Output: %w\n", err)
	}
	if output == (TxVout{}) {
		// we couldn't decode any output from this tx. Which means we don't own any anyway.
		c.logger.Info().Msg("Ignoring a Tx we don't own any output of")
		return types.TxInItem{}, nil
	}

	// TODO: sender id only required for adding liquity. Might get it from memo data when required.
	sender := "hvta8SzCkbTLNFDeJcRL51FrTci7YwGzLGHwJYukhCVAivU43WQVFde9c6n6WmZ8y5fDH3SwajsS5Yy3HUcfFCm63uF1eNspce"

	// TODO: xasset fees can be proportionaly different than regular xhv fees??
	// get the gas
	var fee int64
	if val, ok := parsedTxExtra[0x17]; ok {
		offshoreData := strings.Split(string(val[0]), "-")
		if offshoreData[0] == "XHV" {
			fee = tx.Rct_Signatures.TxnFee
		} else if offshoreData[0] == "XUSD" {
			fee = tx.Rct_Signatures.TxnFee_Usd
		} else {
			fee = tx.Rct_Signatures.TxnFee_Xasset
		}
	} else {
		fee = tx.Rct_Signatures.TxnFee
	}

	// get the coins
	var asset common.Asset
	if output.Asset == "XHV" {
		asset, err = common.NewAsset("XHV." + output.Asset)
	} else {
		asset, err = common.NewAsset("XHV." + output.Asset + "-" + output.Asset)
	}
	if err != nil {
		return types.TxInItem{}, fmt.Errorf("Ignoring a Tx with invalid asset type: %w\n", err)
	}
	coins := common.Coins{
		common.NewCoin(asset, cosmos.NewUint(output.Amount)),
	}

	// get the memo
	memo := ""
	if val, ok := parsedTxExtra[0x18]; ok {
		memo = string(val[0])
	} else {
		return types.TxInItem{}, nil
	}

	return types.TxInItem{
		BlockHeight: height,
		Tx:          tx.Hash,
		Sender:      sender,
		To:          output.Address,
		Coins:       coins,
		Memo:        memo,
		Gas: common.Gas{
			common.NewCoin(common.XHVAsset, cosmos.NewUint((uint64(fee)))),
		},
	}, nil
}

func (c *Client) getOutput(tx *RawTx, txPubKey *[32]byte) (TxVout, error) {

	var txVout = TxVout{}

	// generate the shared secrets for both ygg and asgard
	sharedSecretYgg, err := crypto.GenerateKeyDerivation(txPubKey, &c.ksWrapper.privViewKey)
	if err != nil {
		return txVout, fmt.Errorf("Error Creating Shared Secret: %w\n", err)
	}

	for ind, vout := range tx.Vout {

		var targetKey [32]byte
		assetType := ""
		if len(vout.Target.Key) != 0 {
			targetRaw, _ := hex.DecodeString(vout.Target.Key)
			copy(targetKey[:], targetRaw)
			assetType = "XHV"
		} else if len(vout.Target.Offshore) != 0 {
			targetRaw, _ := hex.DecodeString(vout.Target.Offshore)
			copy(targetKey[:], targetRaw)
			assetType = "XUSD"
		} else if len(vout.Target.Xasset) != 0 {
			targetRaw, _ := hex.DecodeString(vout.Target.Xasset)
			copy(targetKey[:], targetRaw)
			assetType = vout.Target.asset_type
		} else {
			c.logger.Info().Msgf("Invalid tx output found! Skipping..")
			continue
		}

		// derive the spent key
		derivedPublicSpendKeyYgg, err := crypto.SubSecretFromTarget((*sharedSecretYgg)[:], uint64(ind), &targetKey)
		if err != nil {
			return txVout, fmt.Errorf("Error Deriving Ygg Public Spend Key: %w\n", err)
		}

		found := false
		if *derivedPublicSpendKeyYgg == c.pubSpendKey {
			found = true
			c.logger.Info().Msgf("found an output belongs to pubKey = %s", hex.EncodeToString(c.pubSpendKey[:]))
		}

		if found {
			// decode the tx amount and mask
			var scalar *[32]byte
			scalar = crypto.DerivationToScalar((*sharedSecretYgg)[:], uint64(ind))
			ecdhInfo := crypto.EcdhDecode(tx.Rct_Signatures.EcdhInfo[ind], *scalar)

			// Calculate the amount commitment from decoded ecdh info
			var C, Ctmp [32]byte
			success := crypto.AddKeys2(&Ctmp, ecdhInfo.Mask, ecdhInfo.Amount, crypto.H)

			if success {
				if assetType == "XHV" {
					// Onshore amount (XHV)
					Craw, _ := hex.DecodeString(tx.Rct_Signatures.OutPk[ind])
					copy(C[:], Craw)
				} else if assetType == "XUSD" {
					// Offshore amount (xUSD)
					Craw, _ := hex.DecodeString(tx.Rct_Signatures.OutPk_Usd[ind])
					copy(C[:], Craw)
				} else {
					// Xasset amount (xBTC etc)
					Craw, _ := hex.DecodeString(tx.Rct_Signatures.OutPk_Xasset[ind])
					copy(C[:], Craw)
				}

				// check if the provided output commitment mathces with the one we calculated
				if crypto.EqualKeys(C, Ctmp) {

					// populate txVout
					txVout.Address = c.walletAddr.String()
					txVout.Amount = crypto.H2d(ecdhInfo.Amount)
					txVout.Asset = assetType

					// TODO: We can just skip the rest of the outputs and return here because we expect we only own 1 output
					// What about in case of the change that get sent back to us??
					return txVout, nil
				} else {
					c.logger.Info().Msgf("Invalid commitment for ouptut = %d  of tx %s skipiing..", ind, tx.Hash)
				}
			} else {
				c.logger.Info().Msgf("Calculation of the commitment failed for output index = %d of tx %s skipiing..", ind, tx.Hash)
			}
		}
	}

	// We don't own any output in this tx
	return txVout, nil
}

func (c *Client) getAddrFromCndata(cnData string) (common.Address, error) {
	if len(cnData) == 0 {
		return common.NoAddress, fmt.Errorf("Can not get address from empty cn data")
	}
	walletAddr, err := common.PubKey(cnData).GetAddress(common.XHVChain)
	if err != nil {
		return "", fmt.Errorf("Failed to get the wallet address: %w", err)
	}
	return walletAddr, nil
}

func (c *Client) removeFromMemPoolCache(hash string) {
	c.memPoolLock.Lock()
	defer c.memPoolLock.Unlock()
	delete(c.processedMemPool, hash)
}

func (c *Client) tryAddToMemPoolCache(hash string) bool {
	if c.processedMemPool[hash] {
		return false
	}
	c.memPoolLock.Lock()
	defer c.memPoolLock.Unlock()
	c.processedMemPool[hash] = true
	return true
}

// FetchMemPool retrieves txs from mempool
func (c *Client) FetchMemPool(height int64) (types.TxIn, error) {
	// make sure client doesn't scan mempool too much
	diff := time.Now().Sub(c.lastMemPoolScan)
	if diff < constants.ThorchainBlockTime {
		return types.TxIn{}, nil
	}
	c.lastMemPoolScan = time.Now()
	return c.getMemPool(height)
}

func (c *Client) getMemPool(height int64) (types.TxIn, error) {
	hashes, err := GetPoolTxs()
	if err != nil {
		return types.TxIn{}, fmt.Errorf("fail to get tx hashes from mempool: %w", err)
	}
	txIn := types.TxIn{
		Chain:   c.GetChain(),
		MemPool: true,
	}
	for _, h := range hashes {
		// this hash had been processed before , ignore it
		if !c.tryAddToMemPoolCache(h) {
			c.logger.Debug().Msgf("%s had been processed , ignore", h)
			continue
		}

		c.logger.Debug().Msgf("process hash %s", h)
		var txHashes = make([]string, 0)
		txHashes = append(txHashes, h)
		txs, err := GetTxes(txHashes)
		if err != nil {
			return types.TxIn{}, fmt.Errorf("fail to get raw transaction verbose with hash(%s): %w", h, err)
		}
		txInItem, err := c.getTxIn(&(txs[0]), height)
		if err != nil {
			c.logger.Error().Err(err).Msg("fail to get TxInItem")
			continue
		}
		if txInItem.IsEmpty() {
			continue
		}
		txIn.TxArray = append(txIn.TxArray, txInItem)
	}
	// txIn.Count = strconv.Itoa(len(txIn.TxArray))
	return txIn, nil
}

// SignTx is going to generate the outbound transaction, and also sign it
func (c *Client) SignTx(tx stypes.TxOutItem, thorchainHeight int64) ([]byte, error) {

	// check if the chain is correct
	if !tx.Chain.Equals(common.XHVChain) {
		return nil, errors.New("not XHV chain!")
	}

	if tx.ToAddress.IsEmpty() {
		return nil, fmt.Errorf("to address is empty")
	}
	if tx.VaultPubKey.IsEmpty() {
		return nil, fmt.Errorf("vault public key is empty")
	}

	if len(tx.Memo) == 0 {
		return nil, fmt.Errorf("can't sign tx when it doesn't have memo")
	}

	memo, err := mem.ParseMemo(tx.Memo)
	if err != nil {
		return nil, fmt.Errorf("fail to parse memo(%s):%w", tx.Memo, err)
	}

	if memo.IsInbound() {
		return nil, fmt.Errorf("inbound memo should not be used for outbound tx")
	}

	// get the walletAddr for tx vault Pubkey
	vaultAddr, err := c.getAddrFromCndata(c.pkm.GetCnData(tx.VaultPubKey))
	if err != nil {
		return nil, fmt.Errorf("fail to get vaut adddress from tx vaultPubKey: %w", err)
	}

	// get the amount
	if len(tx.Coins) != 1 {
		return nil, fmt.Errorf("Can't sing tx: Haven doesn't support sending multiple asset types in a single transaction!")
	}
	amount := tx.Coins[0].Amount.Uint64()
	outputAsset := tx.Coins[0].Asset.Symbol.String()

	var signedTx CreatedTx
	if vaultAddr.Equals(c.walletAddr) {
		// we are the one who signing this tx.
		c.logger.Info().Msgf("Creating an outbound tx Amount: %d for %s", amount, tx.ToAddress.String())

		// create dsts array
		keyVaule := make(map[string]interface{})
		dsts := make([]map[string]interface{}, 1)
		keyVaule["amount"] = amount
		keyVaule["address"] = tx.ToAddress.String()
		dsts[0] = keyVaule

		// try to login to wallet
		if !loginToWallet("havenBifrost", "passwd") {
			return nil, fmt.Errorf("fail to open the haven wallet")
		} else {
			log.Logger.Info().Msgf("Succesful login to local Haven ygg wallet!")
		}

		// sign tx
		signedTx, err = CreateTx(dsts, outputAsset, tx.Memo)
		if err != nil {
			return nil, err
		}
	} else {
		// tss sign
		dst := wallet.Destination{
			Amount:  amount,
			Address: tx.ToAddress.String(),
		}
		t := wallet.RequestTransfer{
			Destinations:  []*wallet.Destination{&dst},
			GetTxHex:      true,
			RingSize:      11,
			GetTxKey:      true,
			GetTxMetadata: true,
		}
		tx, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		encodedTx := base64.StdEncoding.EncodeToString(tx)
		txKey, txID, err := c.tssKm.RemoteSignMn([]byte(encodedTx), "192.168.1.110")
		if err != nil {
			return nil, err
		}

		// at this point we expect RemoteSignMn() to complete tx construction and submit to haven daemon.
		// But we don't know who signed this tx and whether it is actually correct amount.
		// so check whether it is or not. If not, send error.
		// walletClient.CheckTxKry() is the function

		// concatanete and return the txKey + txID
		res, err := hex.DecodeString(txKey + txID)
		if err != nil {
			return nil, err
		}
		return res, nil
	}

	// TODO: if we create multiple transactions we will have multiple Tx_Blobs. What should we do in that case. Concatanete them?
	bytes, err := hex.DecodeString(signedTx.Tx_Blob_List[0])
	if err != nil {
		return nil, err
	}
	c.lastSignedTxHash = signedTx.Tx_Hash_List[0]
	return bytes, nil
}

// BroadcastTx will broadcast the given payload to XHV chain
func (c *Client) BroadcastTx(txOut stypes.TxOutItem, payload []byte) (string, error) {

	// get the hex of tx to send the daemon
	txHex := hex.EncodeToString(payload)

	if len(txHex) == 64 {
		// this is a tx proof coming from TSS signing instead of tx itself, so return itself directly
		c.logger.Info().Msgf("Recieved a TSS tx subnistion. Tx must be already submitted. TxKey + TxID: %s", txHex)
		return txHex, nil
	}

	// broadcast tx
	resp := SendRawTransaction(txHex)
	if resp.Status != "OK" {
		// TODO: this is a fake reason text. Find the original and replace this.
		if resp.Reason == "TX is alread in the chain" {
			return "", nil
		}
		return "", fmt.Errorf("fail to broadcast transaction to chain: %s", resp.Reason)
	}

	c.logger.Info().Msgf("Succesfuuly submitted transaction to haven daemon hash: %s", c.lastSignedTxHash)
	return c.lastSignedTxHash, nil
}

func (c *Client) parseTxExtra(extra []byte) (map[byte][][]byte, error) {

	var parsedTxExtra = make(map[byte][][]byte)

	for ind := 0; ind < len(extra); ind++ {

		if extra[ind] == 0 {
			// Padding
			var len = int(extra[ind+1])
			ind += len
		} else if extra[ind] == 0x01 {
			// Pubkey - 32 byte key (fixed length)
			if len(extra)-ind <= 32 {
				return nil, fmt.Errorf("Tx pubKey has insufficient length!")
			}
			var ba = make([]byte, 32)
			ba = extra[ind+1 : ind+33]
			parsedTxExtra[0x01] = append(parsedTxExtra[0x01], ba)
			ind += 32
		} else if extra[ind] == 2 {
			// Nonce
			var len = int(extra[ind+1])
			ind += len
		} else if extra[ind] == 3 {
			// Merge mining key
			ind += 40
		} else if extra[ind] == 4 {
			// Additional pubkeys
			ind += 32
		} else if extra[ind] == 0xde {
			// miner gate tag
			var len = int(extra[ind+1])
			ind += len
		} else if extra[ind] == 0x17 {
			// Offshore data
			var length = int(extra[ind+1])
			if len(extra)-ind <= length {
				return nil, fmt.Errorf("Offshore data has insufficient length!")
			}
			var ba = make([]byte, length)
			ba = extra[ind+2 : ind+2+length]
			parsedTxExtra[0x17] = append(parsedTxExtra[0x17], ba)
			ind += length
		} else if extra[ind] == 0x18 {
			// Thorchain memo data
			var length = int(extra[ind+1])
			if len(extra)-ind <= length {
				return nil, fmt.Errorf("Thorchain memo data has insufficient length!")
			}
			var ba = make([]byte, length)
			ba = extra[ind+2 : ind+2+length]
			parsedTxExtra[0x18] = append(parsedTxExtra[0x18], ba)
			ind += length
		}
	}

	return parsedTxExtra, nil
}
