package haven

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	btypes "gitlab.com/thorchain/thornode/bifrost/blockscanner/types"
	"gitlab.com/thorchain/thornode/bifrost/pubkeymanager"
	ttypes "gitlab.com/thorchain/thornode/x/thorchain/types"

	tssp "github.com/akildemir/moneroTss/tss"
	"github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/haven-protocol-org/go-haven-rpc-client/wallet"
	"github.com/haven-protocol-org/monero-go-utils/crypto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/thornode/bifrost/blockscanner"
	"gitlab.com/thorchain/thornode/bifrost/config"
	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	"gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/bifrost/tss"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	mem "gitlab.com/thorchain/thornode/x/thorchain/memo"
)

// Client observes bitcoin chain and allows to sign and broadcast tx
type Client struct {
	logger                zerolog.Logger
	cfg                   config.ChainConfiguration
	walletAddr            common.Address
	processedMemPool      map[string]bool
	memPoolLock           *sync.Mutex
	signedTxOut           map[string]TxOutWitness
	signedTxOutLock       *sync.Mutex
	lastMemPoolScan       time.Time
	currentBlockHeight    int64
	blockScanner          *blockscanner.BlockScanner
	blockMetaAccessor     BlockMetaAccessor
	bridge                *thorclient.ThorchainBridge
	wg                    *sync.WaitGroup
	globalErrataQueue     chan<- types.ErrataBlock
	globalSolvencyQueue   chan<- types.Solvency
	asgardAddresses       []common.Address
	nodePubKey            common.PubKey
	lastAsgard            time.Time
	asgardPassword        string
	pkm                   pubkeymanager.PubKeyValidator
	poolMgr               thorclient.PoolManager
	consolidateInProgress bool
	supportedAssets       []string
	tssKm                 *tss.KeySign
	client                wallet.Client
}

type TxVout struct {
	Address string
	Amount  uint64
	Asset   string
	ind     int
}

type TxOutWitness struct {
	TxID     string
	TxKey    string
	Coin     common.Coin
	Reciever string
	Sender   string
	memo     string
	Asset    common.Asset
}

// BlockCacheSize the number of block meta that get store in storage.
const (
	BlockCacheSize     = 144
	MaxAsgardAddresses = 100
	// EstimateAverageTxSize for THORChain the estimate tx size is hard code to 1000 here , as most of time it will spend 1 input, have 3 output
	// which is average at 250 vbytes , however asgard will consolidate UTXOs , which will take up to 1000 vbytes
	EstimateAverageTxSize = 1000
	// DefaultCoinbaseValue  = 6.25
	// MaxMempoolScanPerTry  = 500
	AverageFeeRate  = 314016568 // atomic units
	maxUTXOsToSpend = 10
)

// NewClient generates a new Client
func NewClient(
	thorKeys *thorclient.Keys,
	cfg config.ChainConfiguration,
	server *tssp.TssServer,
	bridge *thorclient.ThorchainBridge,
	pkm pubkeymanager.PubKeyValidator,
	poolMgr thorclient.PoolManager,
	m *metrics.Metrics) (*Client, error) {

	// set the daemon address
	DaemonHost = cfg.RPCHost

	// create the wallet rpc client
	client := wallet.New(wallet.Config{
		Address: cfg.WalletRPCHost,
	})

	log.Logger.Info().Msgf("Haven Wallet-Rpc IP address %s", cfg.WalletRPCHost)

	// create haven tss server
	tssKm, err := tss.NewKeySignMn(server, bridge)
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

	// generate wallet address
	walletAddr, err := generateWalletAddress(&havenPrivSpendKey, &havenPrivViewKey)
	if err != nil {
		return nil, fmt.Errorf("fail to generatre a haven wallet address: %+v", err)
	}

	// try to generate a haven wallet
	walletResp, err := client.CreateWalletFromKeys(&wallet.RequestCreateWalletFromKeys{
		Filename: cfg.UserName,
		Password: cfg.Password,
		SpendKey: hex.EncodeToString(havenPrivSpendKey[:]),
		ViewKey:  hex.EncodeToString(havenPrivViewKey[:]),
		Address:  walletAddr.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("fail to generatre a haven wallet: %+v", err)
	}
	if len(walletResp.Address) == 0 {
		return nil, fmt.Errorf("unexpected error when generating the haven wallet: %s", walletResp.Info)
	}

	if pkm == nil {
		return nil, errors.New("pubkey manager is nil")
	}
	if poolMgr == nil {
		return nil, errors.New("pool manager is nil")
	}

	c := &Client{
		logger:           log.Logger.With().Str("module", "haven").Logger(),
		cfg:              cfg,
		bridge:           bridge,
		pkm:              pkm,
		poolMgr:          poolMgr,
		nodePubKey:       thorPubkey,
		walletAddr:       walletAddr,
		memPoolLock:      &sync.Mutex{},
		signedTxOutLock:  &sync.Mutex{},
		wg:               &sync.WaitGroup{},
		client:           client,
		tssKm:            tssKm,
		supportedAssets:  []string{"XHV", "XUSD", "XBTC", "XEUR", "XGBP", "XCHF", "XAUD", "XAU", "XAG", "XCNY"},
		asgardPassword:   hex.EncodeToString(common.CosmosPrivateKeyToTMPrivateKey(thorPriveKey).Bytes()),
		processedMemPool: make(map[string]bool),
		signedTxOut:      make(map[string]TxOutWitness),
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
	c.logger.Info().Msgf("Haven Wallet-Rpc IP address %s", cfg.WalletRPCHost)
	return c, nil
}

// Start starts the block scanner
func (c *Client) Start(globalTxsQueue chan types.TxIn, globalErrataQueue chan types.ErrataBlock, globalSolvencyQueue chan types.Solvency) {
	c.globalErrataQueue = globalErrataQueue
	c.globalSolvencyQueue = globalSolvencyQueue
	// c.tssKeySigner.Start()
	c.blockScanner.Start(globalTxsQueue)
}

// Stop stops the block scanner
func (c *Client) Stop() {
	c.blockScanner.Stop()
	c.tssKm.Stop()
	// wait for consolidate utxo to exit
	c.wg.Wait()
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
	height, err := GetChainHeight()
	if err != nil {
		return 0, fmt.Errorf("failed to get height: %+v", err)
	}
	return int64(height), nil
}

// GetAddress return current local haven vault address
func (c *Client) GetAddress(poolPubKey common.PubKey) string {
	return c.walletAddr.String()
}

// GetAccountByAddress return empty account for now
func (c *Client) GetAccountByAddress(address string) (common.Account, error) {
	return common.Account{}, nil
}

func (c *Client) loginToLocalWallet() error {
	err := c.client.OpenWallet(&wallet.RequestOpenWallet{
		Filename: c.cfg.UserName,
		Password: c.cfg.Password,
	})
	return err
}

// GetAccount returns account with balance for an address
func (c *Client) GetAccount(pkey common.PubKey) (common.Account, error) {

	acct := common.Account{}
	if pkey.IsEmpty() {
		return acct, errors.New("pubkey can't be empty")
	}

	//login to wallet
	err := c.loginToLocalWallet()
	if err != nil {
		return acct, fmt.Errorf("fail to login to wallet: %w", err)
	}

	// get the spendable balance of each asset
	// TODO: Ask for decimal place handling.
	var coins []common.Coin
	for _, asset := range c.supportedAssets {
		resp, err := c.client.GetBalance(&wallet.RequestGetBalance{
			AccountIndex: 0,
			AssetType:    asset,
		})
		if err != nil {
			return acct, fmt.Errorf("fail to get the balance: %w", err)
		}
		if resp.UnlockedBalance != 0 {
			a, err := common.NewAsset("XHV." + asset)
			if err != nil {
				return acct, fmt.Errorf("fail tconstruct asset: %w", err)
			}
			coins = append(coins, common.NewCoin(a, cosmos.NewUint(uint64(resp.UnlockedBalance))))
		}
	}

	// we should always close the wallet after usage since there will be only one rpc server running
	// and some other wallet(multisig asgard for example) might always want to login
	err = c.client.CloseWallet()
	if err != nil {
		return acct, fmt.Errorf("fail to close the wallet: %w", err)
	}

	// return a new Account with the total amount spendable.
	return common.NewAccount(0, 0, coins, false), nil
}

func (c *Client) getTotalTransactionValue(txIn types.TxIn, excludeFrom []common.Address) cosmos.Uint {
	total := cosmos.ZeroUint()
	if len(txIn.TxArray) == 0 {
		return total
	}
	for _, item := range txIn.TxArray {
		fromAsgard := false
		for _, fromAddress := range excludeFrom {
			if strings.EqualFold(fromAddress.String(), item.Sender) {
				fromAsgard = true
				break
			}
		}
		if fromAsgard {
			continue
		}
		// if from address is yggdrasil , exclude the value from confirmation counting
		ok, _ := c.pkm.IsValidPoolAddress(item.Sender, common.XHVChain)
		if ok {
			continue
		}
		for _, coin := range item.Coins {
			if coin.IsEmpty() {
				continue
			}
			amount := coin.Amount
			if !coin.Asset.Equals(common.XHVAsset) {
				var err error
				amount, err = c.poolMgr.GetValue(coin.Asset, common.XHVAsset, coin.Amount)
				if err != nil {
					c.logger.Err(err).Msgf("fail to get value for %s", coin.Asset)
					continue
				}

			}
			total = total.Add(amount)
		}
	}
	return total
}

func (c *Client) getCoinbaseValue(blockHeight int64) (cosmos.Uint, error) {

	// get block
	block, err := GetBlock(blockHeight)
	if err != nil {
		return cosmos.Uint{}, fmt.Errorf("fail to get block verbose tx: %v", err)
	}

	total := cosmos.ZeroUint()
	for _, reward := range block.Block_Header.Rewards {
		amount := cosmos.NewUint(reward.Amount)
		if reward.AssetType != "XHV" {
			asset, err := common.NewAsset("XHV." + reward.AssetType)
			if err != nil {
				c.logger.Err(err).Msgf("fail to make asset for %s", reward.AssetType)
				continue
			}

			amount, err = c.poolMgr.GetValue(asset, common.XHVAsset, amount)
			if err != nil {
				c.logger.Err(err).Msgf("fail to get value for %s", asset)
				continue
			}
		}
		total = total.Add(amount)
	}

	return total, nil
}

func (c *Client) IsBlockScannerHealthy() bool {
	return c.blockScanner.IsHealthy()
}

// getBlockRequiredConfirmation find out how many confirmation the given txIn need to have before it can be send to THORChain
func (c *Client) getBlockRequiredConfirmation(txIn types.TxIn, height int64) (int64, error) {
	totalTxValue := c.getTotalTransactionValue(txIn, c.asgardAddresses)
	totalFeeAndSubsidy, err := c.getCoinbaseValue(height)
	if err != nil {
		return 0, fmt.Errorf("fail to get coinbase value: %w", err)
	}
	confirm := totalTxValue.MulUint64(2).Quo(totalFeeAndSubsidy).Uint64()
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

	var confirm int64 = 10
	reqConfirm, err := c.getBlockRequiredConfirmation(txIn, blockHeight)
	if reqConfirm > confirm {
		confirm = reqConfirm
	}
	c.logger.Info().Msgf("confirmation required: %d", confirm)
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
	blockMeta, err := c.blockMetaAccessor.GetBlockMeta(blockHeight)
	if err != nil {
		c.logger.Err(err).Msgf("fail to get block meta on block height(%d)", blockHeight)
		return
	}
	if blockMeta == nil {
		blockMeta = NewBlockMeta("", blockHeight, "")
	}
	if _, err := c.blockMetaAccessor.TryAddToObservedTxCache(txIn.Tx); err != nil {
		c.logger.Err(err).Msgf("fail to add hash (%s) to observed tx cache", txIn.Tx)
	}
	if c.isAsgardAddress(txIn.Sender) {
		c.logger.Debug().Msgf("add hash %s as self transaction,block height:%d", txIn.Tx, blockHeight)
		blockMeta.AddSelfTransaction(txIn.Tx)
	} else {
		// add the transaction to block meta
		blockMeta.AddCustomerTransaction(txIn.Tx)
	}
	if err := c.blockMetaAccessor.SaveBlockMeta(blockHeight, blockMeta); err != nil {
		c.logger.Err(err).Msgf("fail to save block meta to storage,block height(%d)", blockHeight)
	}
}

func (c *Client) getAsgardAddress() ([]common.Address, error) {
	if time.Since(c.lastAsgard) < constants.ThorchainBlockTime && c.asgardAddresses != nil {
		return c.asgardAddresses, nil
	}
	vaults, err := c.bridge.GetAsgards()
	if err != nil {
		return nil, fmt.Errorf("fail to get asgards : %w", err)
	}

	for _, v := range vaults {
		addr, err := common.PubKey(v.CryptonoteData).GetAddress(common.XHVChain)
		if err != nil {
			c.logger.Err(err).Msg("fail to get address")
			continue
		}
		found := false
		for _, item := range c.asgardAddresses {
			if item.Equals(addr) {
				found = true
				break
			}
		}
		if !found {
			c.asgardAddresses = append(c.asgardAddresses, addr)
		}
	}
	if len(c.asgardAddresses) > MaxAsgardAddresses {
		startIdx := len(c.asgardAddresses) - MaxAsgardAddresses
		c.asgardAddresses = c.asgardAddresses[startIdx:]
	}
	c.lastAsgard = time.Now()
	return c.asgardAddresses, nil
}

func (c *Client) isAsgardAddress(addressToCheck string) bool {
	asgards, err := c.getAsgardAddress()
	if err != nil {
		c.logger.Err(err).Msg("fail to get asgard addresses")
		return false
	}
	for _, addr := range asgards {
		if strings.EqualFold(addr.String(), addressToCheck) {
			return true
		}
	}
	return false
}

// FetchTxs retrieves txs for a block height
func (c *Client) FetchTxs(height int64) (types.TxIn, error) {

	txIn := types.TxIn{
		Chain:   common.XHVChain,
		TxArray: nil,
	}
	block, err := GetBlock(height)
	if err != nil {
		return txIn, btypes.UnavailableBlock
	}

	// if somehow the block is not valid
	if block.Block_Header.Hash == "" && block.Block_Header.Prev_Hash == "" {
		return txIn, fmt.Errorf("fail to get block: %w", err)
	}
	c.currentBlockHeight = height
	c.logger.Info().Int64("block height", c.currentBlockHeight).Msg("fetch txs")
	reScannedTxs, err := c.processReorg(block)
	if err != nil {
		c.logger.Err(err).Msg("fail to process bitcoin re-org")
	}
	if len(reScannedTxs) > 0 {
		for _, item := range reScannedTxs {
			if len(item.TxArray) == 0 {
				continue
			}
			txIn.TxArray = append(txIn.TxArray, item.TxArray...)
		}
	}

	// update block meta
	blockMeta, err := c.blockMetaAccessor.GetBlockMeta(block.Block_Header.Height)
	if err != nil {
		return types.TxIn{}, fmt.Errorf("fail to get block meta from storage: %w", err)
	}
	if blockMeta == nil {
		blockMeta = NewBlockMeta(block.Block_Header.Prev_Hash, block.Block_Header.Height, block.Block_Header.Hash)
	} else {
		blockMeta.PreviousHash = block.Block_Header.Prev_Hash
		blockMeta.BlockHash = block.Block_Header.Hash
	}
	if err := c.blockMetaAccessor.SaveBlockMeta(block.Block_Header.Height, blockMeta); err != nil {
		return types.TxIn{}, fmt.Errorf("fail to save block meta into storage: %w", err)
	}

	// update prune block meta
	pruneHeight := height - BlockCacheSize
	if pruneHeight > 0 {
		defer func() {
			if err := c.blockMetaAccessor.PruneBlockMeta(pruneHeight, c.canDeleteBlock); err != nil {
				c.logger.Err(err).Msgf("fail to prune block meta, height(%d)", pruneHeight)
			}
		}()
	}

	txInBlock, err := c.extractTxs(block)
	if err != nil {
		return types.TxIn{}, fmt.Errorf("fail to extract txIn from block: %w", err)
	}
	if len(txInBlock.TxArray) > 0 {
		txIn.TxArray = append(txIn.TxArray, txInBlock.TxArray...)
	}
	if err := c.sendNetworkFee(height); err != nil {
		c.logger.Err(err).Msg("fail to send network fee")
	}
	if err := c.reportSolvency(height); err != nil {
		c.logger.Err(err).Msgf("fail to send solvency info to THORChain")
	}
	txIn.Count = strconv.Itoa(len(txIn.TxArray))
	if !c.consolidateInProgress {
		// try to consolidate UTXOs
		c.wg.Add(1)
		go c.consolidateUTXOs()
	}
	return txIn, nil
}

func (c *Client) canDeleteBlock(blockMeta *BlockMeta) bool {
	if blockMeta == nil {
		return true
	}
	for _, tx := range blockMeta.SelfTransactions {
		if c.txInThePool(&tx) {
			c.logger.Info().Msgf("tx: %s still in mempool , block can't be deleted", tx)
			return false
		}
	}
	return true
}

func (c *Client) sendNetworkFee(height int64) error {
	txid, err := c.bridge.PostNetworkFee(height, common.XHVChain, uint64(EstimateAverageTxSize), uint64(AverageFeeRate))
	if err != nil {
		return fmt.Errorf("fail to post network fee to thornode: %w", err)
	}
	c.logger.Debug().Str("txid", txid.String()).Msg("send network fee to THORNode successfully")
	return nil
}

func (c *Client) processReorg(block Block) ([]types.TxIn, error) {
	previousHeight := block.Block_Header.Height - 1
	prevBlockMeta, err := c.blockMetaAccessor.GetBlockMeta(previousHeight)
	if err != nil {
		return nil, fmt.Errorf("fail to get block meta of height(%d) : %w", previousHeight, err)
	}
	if prevBlockMeta == nil {
		return nil, nil
	}
	// the block's previous hash need to be the same as the block hash chain client recorded in block meta
	// blockMetas[PreviousHeight].BlockHash == Block.PreviousHash
	if strings.EqualFold(prevBlockMeta.BlockHash, block.Block_Header.Prev_Hash) {
		return nil, nil
	}

	c.logger.Info().Msgf("re-org detected, current block height:%d ,previous block hash is : %s , however block meta at height: %d, block hash is %s", block.Block_Header.Height, block.Block_Header.Prev_Hash, prevBlockMeta.Height, prevBlockMeta.BlockHash)
	blockHeights, err := c.reConfirmTx()
	if err != nil {
		c.logger.Err(err).Msgf("fail to reprocess all txs")
	}
	var txIns []types.TxIn
	for _, item := range blockHeights {
		c.logger.Info().Msgf("rescan block height: %d", item)
		b, err := GetBlock(item)
		if err != nil {
			c.logger.Err(err).Msgf("fail to get block from RPC for height:%d", item)
			continue
		}
		txIn, err := c.extractTxs(b)
		if err != nil {
			c.logger.Err(err).Msgf("fail to extract txIn from block")
			continue
		}

		if len(txIn.TxArray) == 0 {
			continue
		}
		txIns = append(txIns, txIn)
	}
	return txIns, nil
}

// reConfirmTx will be kicked off only when chain client detected a re-org on bitcoin chain
// it will read through all the block meta data from local storage , and go through all the UTXOes.
// For each UTXO , it will send a RPC request to bitcoin chain , double check whether the TX exist or not
// if the tx still exist , then it is all good, if a transaction previous we detected , however doesn't exist anymore , that means
// the transaction had been removed from chain,  chain client should report to thorchain
func (c *Client) reConfirmTx() ([]int64, error) {
	blockMetas, err := c.blockMetaAccessor.GetBlockMetas()
	if err != nil {
		return nil, fmt.Errorf("fail to get block metas from local storage: %w", err)
	}
	var rescanBlockHeights []int64
	for _, blockMeta := range blockMetas {
		var errataTxs []types.ErrataTx
		for _, txHash := range blockMeta.CustomerTransactions {
			if c.confirmTx(txHash) {
				c.logger.Info().Msgf("block height: %d, tx: %s still exist", blockMeta.Height, txHash)
				continue
			}
			// this means the tx doesn't exist in chain ,thus should errata it
			errataTxs = append(errataTxs, types.ErrataTx{
				TxID:  common.TxID(txHash),
				Chain: common.XHVChain,
			})
			// remove the UTXO from block meta , so signer will not spend it
			blockMeta.RemoveCustomerTransaction(txHash)
		}
		if len(errataTxs) > 0 {
			c.globalErrataQueue <- types.ErrataBlock{
				Height: blockMeta.Height,
				Txs:    errataTxs,
			}
		}
		// Let's get the block again to fix the block hash
		r, err := GetBlock(blockMeta.Height)
		if err != nil {
			c.logger.Err(err).Msgf("fail to get block verbose tx result: %d", blockMeta.Height)
		}
		if !strings.EqualFold(blockMeta.BlockHash, r.Block_Header.Hash) {
			rescanBlockHeights = append(rescanBlockHeights, blockMeta.Height)
		}
		blockMeta.PreviousHash = r.Block_Header.Prev_Hash
		blockMeta.BlockHash = r.Block_Header.Hash
		if err := c.blockMetaAccessor.SaveBlockMeta(blockMeta.Height, blockMeta); err != nil {
			c.logger.Err(err).Msgf("fail to save block meta of height: %d ", blockMeta.Height)
		}
	}
	return rescanBlockHeights, nil
}

func (c *Client) txInThePool(txHash *string) bool {
	// get pool txs
	poolTxs, err := GetPoolTxs()
	if err != nil {
		c.logger.Err(err).Msgf("fail to get pool txs result: %w", err)
		return false
	}

	// check if the tx is in the pool.
	for _, tx := range poolTxs {
		if tx == *txHash {
			return true
		}
	}
	return false
}

// confirmTx check a tx is valid on chain post reorg
func (c *Client) confirmTx(txHash string) bool {
	// first check if tx is in mempool, just signed it for example
	// if no error it means its valid mempool tx and move on
	if c.txInThePool(&txHash) {
		return true
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
	currentHeight, err := GetChainHeight()
	if err != nil {
		c.logger.Err(err).Msgf("Error getting current height")
		return false
	}
	if currentHeight > txs[0].Block_Height {
		return true
	}

	return false
}

func (c *Client) processOutgoing(tx *RawTx, height int64, inBlock bool) types.TxInItem {
	c.signedTxOutLock.Lock()
	defer c.signedTxOutLock.Unlock()

	var txInItem types.TxInItem
	var txOutHash string

	// check for outgoing txs that we submitted
	for h, w := range c.signedTxOut {

		if len(w.TxID) == 0 {
			// query tc to get the txkey for this tx
			txInItem, err := c.bridge.GetTx(tx.Hash)
			if err != nil {
				c.logger.Error().Msgf("error getting witness tx from thorhcain: %w", err)
				continue
			}
			if txInItem.IsEmpty() {
				// this is expected here till the node that signed the
				// outgoing tx send it is witness to thorhcain.
				continue
			}

			// check whether this witness is for this tx
			if txInItem.Sender == w.Sender && txInItem.To == w.Reciever && txInItem.Coins[0].Equals(w.Coin) {
				w.TxID = txInItem.Tx
				w.TxKey = txInItem.TxKey
				c.signedTxOut[h] = w
			} else {
				continue
			}
		}

		// check whether this witness is for this tx
		if w.TxID != tx.Hash {
			continue
		}

		// check if we can verifty the txIn if we are not the sender
		verified := false
		if w.Sender != c.walletAddr.String() {
			// someone else signed this outoing
			respCheck, err := c.client.CheckTxKey(&wallet.RequestCheckTxKey{
				TxID:    txInItem.Tx,
				TxKey:   txInItem.TxKey,
				Address: w.Reciever, // it is important to take this from our own cache because sender might change it.
			})
			if err != nil {
				c.logger.Error().Msgf("error checking for txkey for tx %s, err: %v", tx.Hash, err)
				break
			}

			// we expect that address to recieve only 1 asset type, thus lenght of ReceivedAmounts should be 1
			if len(respCheck.ReceivedAmounts) == 1 && len(respCheck.ReceivedAssets) == 1 &&
				respCheck.ReceivedAmounts[0] == w.Coin.Amount.Uint64() &&
				respCheck.ReceivedAssets[0] == w.Coin.Asset.Ticker.String() {
				verified = true
			}
		}

		if w.Sender == c.walletAddr.String() || verified {
			txInItem = types.TxInItem{
				BlockHeight: height,
				Tx:          w.TxID,
				TxKey:       w.TxKey,
				Memo:        w.memo,
				Sender:      w.Sender,
				To:          w.Reciever,
				Coins:       []common.Coin{w.Coin},
				Gas: common.Gas{
					common.NewCoin(w.Coin.Asset, cosmos.NewUint(tx.Rct_Signatures.TxnFee)),
				},
			}
		}
		txOutHash = h
		break
	}

	// dont delete the witness if the tx is still in the mempool
	// we will need the same thing when the tx is in a block
	if !txInItem.IsEmpty() && inBlock {
		delete(c.signedTxOut, txOutHash)
	}

	return txInItem
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
		return txIn, fmt.Errorf("failed to get txs from daemon: %w", err)
	}

	// populate txItems
	var txItems []types.TxInItem
	for _, tx := range txs {
		// remove from pool cache
		c.removeFromMemPoolCache(tx.Hash)

		// get txInItem
		inBlock := true
		txInItem, err := c.getTxIn(&tx, block.Block_Header.Height, inBlock)
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

func (c *Client) getTxIn(tx *RawTx, height int64, inBlock bool) (types.TxInItem, error) {

	txInTem := c.processOutgoing(tx, height, inBlock)
	if !txInTem.IsEmpty() {
		return txInTem, nil
	}

	// parse tx extra
	parsedTxExtra, err := c.parseTxExtra(tx.Extra)
	if err != nil {
		return types.TxInItem{}, fmt.Errorf("error Parsing Tx Extra: %w", err)
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
		return types.TxInItem{}, fmt.Errorf("error Decrypting Tx Output: %w", err)
	}
	if output == (TxVout{}) {
		// we couldn't decode any output from this tx. Which means we don't own any anyway.
		return types.TxInItem{}, nil
	}
	fee := tx.Rct_Signatures.TxnFee

	// get the coins
	asset, err := common.NewAsset("XHV." + output.Asset)
	if err != nil {
		return types.TxInItem{}, fmt.Errorf("ignoring a tx with invalid asset type: %w", err)
	}
	coins := common.Coins{
		common.NewCoin(asset, cosmos.NewUint(output.Amount)),
	}

	// get the memo
	memoStr := ""
	if val, ok := parsedTxExtra[0x18]; ok {
		memoStr = string(val[0])
	} else {
		return types.TxInItem{}, nil
	}

	// check it is a valid memo
	memo, err := mem.ParseMemo(memoStr)
	if err != nil {
		return types.TxInItem{}, fmt.Errorf("ignoring a tx with invalid memo: %w", err)
	}

	// retrive the sender address
	var sender string
	if memo.GetType() == mem.TxAdd || memo.GetType() == mem.TxSwap {
		sender = memo.GetSender().String()
	}

	// all incomings must have a sender. All outgoings + internals should  be filtered in processOutgoing
	if len(sender) == 0 {
		return types.TxInItem{}, fmt.Errorf("ignoring a tx we cant know the sender")
	}

	// check unlock time is 0(default 10 block)
	if tx.Output_Unlock_Times[output.ind] != 0 {
		return types.TxInItem{}, fmt.Errorf("ignoring a tx with non-default unlock time")
	}

	return types.TxInItem{
		BlockHeight: height,
		Tx:          tx.Hash,
		Sender:      sender,
		To:          output.Address,
		Coins:       coins,
		Memo:        memoStr,
		Gas: common.Gas{
			common.NewCoin(asset, cosmos.NewUint(fee)),
		},
	}, nil
}

func (c *Client) getOutput(tx *RawTx, txPubKey *[32]byte) (TxVout, error) {

	// get all vaults keys and check for outputs
	pubkeys, err := c.bridge.GetPubKeys()
	if err != nil {
		return TxVout{}, fmt.Errorf("FAiled to get the asgard vaults: %w", err)
	}
	for _, pk := range pubkeys {
		if len(pk.CryptonoteData) == 0 {
			continue
		}

		// get the privViewKey and pubSpendKey of the vault
		privViewKey, pubSpendKey, err := c.decodeCnData(pk.CryptonoteData)
		if err != nil {
			return TxVout{}, fmt.Errorf("error decoding cryotonote data for vault: %s : %w", pk.PubKey, err)
		}

		sharedSecretYgg, err := crypto.GenerateKeyDerivation(txPubKey, &privViewKey)
		if err != nil {
			return TxVout{}, fmt.Errorf("error Creating Shared Secret: %w", err)
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
				return TxVout{}, fmt.Errorf("error Deriving Ygg Public Spend Key: %w", err)
			}

			found := false
			if *derivedPublicSpendKeyYgg == pubSpendKey {
				found = true
				c.logger.Info().Msgf("found an output belongs to vault = %s", pk.PubKey)
			}

			if found {
				// decode the tx amount and mask
				scalar := crypto.DerivationToScalar((*sharedSecretYgg)[:], uint64(ind))
				ecdhInfo := crypto.EcdhDecode(tx.Rct_Signatures.EcdhInfo[ind], *scalar)

				// Calculate the amount commitment from decoded ecdh info
				var C, Ctmp [32]byte
				success := crypto.AddKeys2(&Ctmp, ecdhInfo.Mask, ecdhInfo.Amount, crypto.H)

				if success {
					Craw, _ := hex.DecodeString(tx.Rct_Signatures.OutPk[ind])

					// check if the provided output commitment mathces with the one we calculated
					copy(C[:], Craw)
					if crypto.EqualKeys(C, Ctmp) {
						// we can ignnore the error because we know cn data is legit at this point.
						addr, _ := c.getAddrFromCndata(pk.CryptonoteData)
						// We can just skip the rest of the outputs and return here because we expect we only own 1 output
						return TxVout{
							Address: addr.String(),
							Amount:  crypto.H2d(ecdhInfo.Amount),
							Asset:   assetType,
							ind:     ind,
						}, nil
					} else {
						c.logger.Info().Msgf("Invalid commitment for ouptut = %d  of tx %s skipiing..", ind, tx.Hash)
					}
				} else {
					c.logger.Info().Msgf("Calculation of the commitment failed for output index = %d of tx %s skipiing..", ind, tx.Hash)
				}
			}
		}
	}

	return TxVout{}, nil
}

func (c *Client) getAddrFromCndata(cnData string) (common.Address, error) {
	if len(cnData) == 0 {
		return common.NoAddress, fmt.Errorf("can not get address from empty cn data")
	}
	walletAddr, err := common.PubKey(cnData).GetAddress(common.XHVChain)
	if err != nil {
		return "", fmt.Errorf("failed to get the wallet address: %w", err)
	}
	return walletAddr, nil
}

func (c *Client) decodeCnData(cnData string) (privViewKey [32]byte, pubSpendKey [32]byte, err error) {
	if len(cnData) == 0 {
		return privViewKey, pubSpendKey, fmt.Errorf("empty cryptonote data")
	}
	asByte, err := hex.DecodeString(cnData)
	if err != nil {
		return privViewKey, pubSpendKey, err
	}
	copy(privViewKey[:], asByte[:32])
	copy(pubSpendKey[:], asByte[32:])
	return
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
	diff := time.Since(c.lastMemPoolScan)
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
		inBlock := false
		txInItem, err := c.getTxIn(&(txs[0]), height, inBlock)
		if err != nil {
			c.logger.Error().Err(err).Msg("fail to get TxInItem")
			continue
		}
		if txInItem.IsEmpty() {
			continue
		}
		txIn.TxArray = append(txIn.TxArray, txInItem)
	}
	txIn.Count = strconv.Itoa(len(txIn.TxArray))
	return txIn, nil
}

// SignTx is going to generate the outbound transaction, and also sign it
func (c *Client) SignTx(tx types.TxOutItem, thorchainHeight int64) ([]byte, error) {

	// check if the chain is correct
	if !tx.Chain.Equals(common.XHVChain) {
		return nil, errors.New("tx is not for XHV chain")
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
	vaultAddr, err := c.getAddrFromCndata(c.pkm.GetCnData(common.XHVChain, tx.VaultPubKey))
	if err != nil {
		return nil, fmt.Errorf("fail to get vaut adddress from tx vaultPubKey: %w", err)
	}

	// get the amount asset type
	if len(tx.Coins) != 1 {
		return nil, fmt.Errorf("can't sing tx: Haven doesn't support sending multiple asset types in a single transaction")
	}
	amount := tx.Coins[0].Amount.Uint64()
	outputAsset := tx.Coins[0].Asset.Ticker.String()

	dst := wallet.Destination{
		Amount:  amount,
		Address: tx.ToAddress.String(),
	}
	t := wallet.RequestTransfer{
		Destinations:  []*wallet.Destination{&dst},
		GetTxHex:      true,
		GetTxKey:      true,
		GetTxMetadata: true,
		RingSize:      11,
		Memo:          tx.Memo,
		AssetType:     outputAsset,
	}
	var txID string
	var txKey string
	var res []byte
	if c.isYggdrasil(tx.VaultPubKey) {
		// we are the one who signing this tx.
		c.logger.Info().Msgf("Creating an outbound tx Amount: %d %s for %s", amount, outputAsset, tx.ToAddress.String())

		// try to login to wallet
		if err := c.loginToLocalWallet(); err != nil {
			return nil, fmt.Errorf("fail to login to wallet: %w", err)
		}

		// sign tx
		signedTx, err := c.client.Transfer(&t)
		if err != nil {
			return nil, fmt.Errorf("fail to make a outgoing transaction: %w", err)
		}

		// logout the wallet
		if err = c.client.CloseWallet(); err != nil {
			return nil, fmt.Errorf("fail to close the wallet: %w", err)
		}

		res, err = hex.DecodeString(signedTx.TxBlob)
		if err != nil {
			return nil, err
		}
		txID = signedTx.TxHash
		txKey = signedTx.TxKey
	} else {
		// check whether we need to taker part in this signing or not
		vaults, err := c.bridge.GetAsgards()
		if err != nil {
			return nil, fmt.Errorf("fail to get asgards : %w", err)
		}
		sign := false
		for _, v := range vaults {
			member := false
			for _, m := range v.Membership {
				if m == c.nodePubKey.String() {
					member = true
				}
			}
			if v.PubKey == tx.VaultPubKey && member {
				sign = true
			}
		}
		if sign {
			c.logger.Info().Msgf("Creating an outbound from asgard tx Amount: %d %s for %s", amount, outputAsset, tx.ToAddress.String())
			// tss sign
			msg, err := json.Marshal(t)
			if err != nil {
				return nil, err
			}
			txKey, txID, err = c.tssKm.RemoteSignMn(msg, tx.VaultPubKey.String(), c.cfg.WalletRPCHost)
			if err != nil {
				return nil, err
			}

			// at this point we expect RemoteSignMn() to complete tx construction and submit to haven daemon.
			// as well check whether it is legit or not.
		}
	}

	// save to be sent from FetchTxs()
	c.signedTxOutLock.Lock()
	defer c.signedTxOutLock.Unlock()
	wtx := TxOutWitness{
		TxID:     txID,
		TxKey:    txKey,
		Coin:     tx.Coins[0],
		Reciever: tx.ToAddress.String(),
		Sender:   vaultAddr.String(),
		memo:     tx.Memo,
	}
	c.signedTxOut[tx.Hash()] = wtx

	return res, nil
}

// BroadcastTx will broadcast the given payload to XHV chain
func (c *Client) BroadcastTx(txOut types.TxOutItem, payload []byte) (string, error) {

	// get txOut hash
	c.signedTxOutLock.Lock()
	txHash := c.signedTxOut[txOut.Hash()].TxID
	c.signedTxOutLock.Unlock()
	if len(txHash) == 0 {
		return "", fmt.Errorf("can't broadcast a tx without tx hash")
	}

	// get the block meta
	height, err := GetChainHeight()
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

	// broadcast tx if we signed it. If it we did tss, it already broadcasted.
	if c.isYggdrasil(txOut.VaultPubKey) {
		resp := SendRawTransaction(hex.EncodeToString(payload))
		if resp.Status != "OK" {
			return "", fmt.Errorf("fail to broadcast transaction to chain: %s", resp.Reason)
		}
	}

	// save tx id to block meta in case we need to errata later
	bm.AddSelfTransaction(txHash)
	c.logger.Info().Str("hash", txHash).Msg("broadcast to XHV chain successfully")
	return txHash, nil
}

func (c *Client) reportSolvency(bitcoinBlockHeight int64) error {
	asgardVaults, err := c.bridge.GetAsgards()
	if err != nil {
		return fmt.Errorf("fail to get asgards,err: %w", err)
	}
	for _, asgard := range asgardVaults {
		acct, err := c.GetAccount(asgard.PubKey)
		if err != nil {
			c.logger.Err(err).Msgf("fail to get account balance")
			continue
		}
		select {
		case c.globalSolvencyQueue <- types.Solvency{
			Height: bitcoinBlockHeight,
			Chain:  common.XHVChain,
			PubKey: asgard.PubKey,
			Coins:  acct.Coins,
		}:
		case <-time.After(constants.ThorchainBlockTime):
			c.logger.Info().Msgf("fail to send solvency info to THORChain, timeout")
		}
	}
	return nil
}

// getUTXOs send a request to wallet-rpc
func (c *Client) getUTXOs(pkey common.PubKey, assetTye string) ([]wallet.TransferDetail, error) {
	if c.isYggdrasil(pkey) {
		err := c.loginToLocalWallet()
		if err != nil {
			return nil, err
		}
	} else {
		// login to asgard wallet
		err := c.client.OpenWallet(&wallet.RequestOpenWallet{
			Filename: c.nodePubKey.String() + ".mo",
			Password: c.asgardPassword,
		})
		if err != nil {
			return nil, err
		}
	}

	// get the all non-spent outs
	res, err := c.client.IncomingTransfers(&wallet.RequestIncomingTransfers{
		TransferType: "available", // get only unspent outputs
	})
	if err != nil {
		return nil, err
	}

	// filter by asset type and unlocked
	var tds []wallet.TransferDetail
	for _, td := range res.Transfers {
		if td.AssetType == assetTye && !td.Frozen && td.Unlocked {
			tds = append(tds, td)
		}
	}

	return tds, nil
}

// isYggdrasil - when the pubkey and node pubkey is the same that means it is signing from yggdrasil
func (c *Client) isYggdrasil(key common.PubKey) bool {
	return key.Equals(c.nodePubKey)
}

// getAllUtxos go through all the block meta in the local storage, it will spend all UTXOs in  block that might be evicted from local storage soon
// it also try to spend enough UTXOs that can add up to more than the given total
func (c *Client) getUtxoToSpend(pubKey common.PubKey) (map[string][]wallet.TransferDetail, error) {
	var result = make(map[string][]wallet.TransferDetail)
	for _, asset := range c.supportedAssets {

		utxos, err := c.getUTXOs(pubKey, asset)
		if err != nil {
			return nil, fmt.Errorf("fail to get UTXOs: %w", err)
		}

		// spend UTXO older to younger
		sort.SliceStable(utxos, func(i, j int) bool {
			if utxos[i].BlockHeight < utxos[j].BlockHeight {
				return true
			} else if utxos[i].BlockHeight > utxos[j].BlockHeight {
				return false
			}
			return utxos[i].GlobalIndex < utxos[j].GlobalIndex
		})
		result[asset] = utxos
	}

	return result, nil
}

func (c *Client) getMaximumUtxosToSpend() int64 {
	const mimirMaxUTXOsToSpend = `MaxUTXOsToSpend`
	utxosToSpend, err := c.bridge.GetMimir(mimirMaxUTXOsToSpend)
	if err != nil {
		c.logger.Err(err).Msg("fail to get MaxUTXOsToSpend")
	}
	if utxosToSpend <= 0 {
		utxosToSpend = maxUTXOsToSpend
	}
	return utxosToSpend
}

// consolidateUTXOs only required when there is a new block
func (c *Client) consolidateUTXOs() {
	defer func() {
		c.wg.Done()
		c.consolidateInProgress = false
	}()
	// TODO: Isn't it just better to use sweep functions? sweep_all or below?
	// it will auto spend all unlcoked outputs and wont have change output.
	// but will lock entire wallet balance for 10 blocks.
	nodeStatus, err := c.bridge.FetchNodeStatus()
	if err != nil {
		c.logger.Err(err).Msg("fail to get node status")
		return
	}
	if nodeStatus != ttypes.NodeStatus_Active {
		c.logger.Info().Msgf("node is not active , doesn't need to consolidate utxos")
		return
	}
	vaults, err := c.bridge.GetAsgards()
	if err != nil {
		c.logger.Err(err).Msg("fail to get current asgards")
		return
	}
	utxosToSpend := c.getMaximumUtxosToSpend()
	for _, vault := range vaults {

		utxoMap, err := c.getUtxoToSpend(vault.PubKey)
		if err != nil {
			c.logger.Err(err).Msg("fail to get utxos to spend")
			continue
		}

		for a, utxos := range utxoMap {

			// doesn't have enough UTXOs , don't need to consolidate
			if int64(len(utxos)) < utxosToSpend {
				continue
			}
			var total uint64 = 0
			for _, item := range utxos {
				total += item.Amount
			}
			addr, err := common.PubKey(vault.CryptonoteData).GetAddress(common.XHVChain)
			if err != nil {
				c.logger.Err(err).Msgf("fail to get XHV address for cn data: %s", vault.CryptonoteData)
				continue
			}

			// THORChain usually pay 1.5 of the last observed fee rate
			feeRate := AverageFeeRate

			asset, err := common.NewAsset("XHV." + a)
			if err != nil {
				c.logger.Err(err).Msgf("fail to create the asset: %v", err)
				continue
			}

			txOutItem := types.TxOutItem{
				Chain:       common.XHVChain,
				ToAddress:   addr,
				VaultPubKey: vault.PubKey,
				Coins: common.Coins{
					common.NewCoin(asset, cosmos.NewUint(uint64(total))),
				},
				Memo:    mem.NewConsolidateMemo().String(),
				MaxGas:  nil,
				GasRate: int64(feeRate),
			}
			height, err := c.bridge.GetBlockHeight()
			if err != nil {
				c.logger.Err(err).Msg("fail to get THORChain block height")
				continue
			}
			rawTx, err := c.SignTx(txOutItem, height)
			if err != nil {
				c.logger.Err(err).Msg("fail to sign consolidate txout item")
				continue
			}
			if len(rawTx) == 0 {
				// this will happen for asgard txs since tss already submits them.
				c.logger.Info().Msgf("broadcast consolidate tx successfully")
				continue
			}
			txID, err := c.BroadcastTx(txOutItem, rawTx)
			if err != nil {
				c.logger.Err(err).Msg("fail to broadcast consolidate tx")
				continue
			}
			c.logger.Info().Msgf("broadcast consolidate tx successfully,hash:%s", txID)
		}

	}
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
				return nil, fmt.Errorf("tx pubKey has insufficient length")
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
				return nil, fmt.Errorf("offshore data has insufficient length")
			}
			var ba = make([]byte, length)
			ba = extra[ind+2 : ind+2+length]
			parsedTxExtra[0x17] = append(parsedTxExtra[0x17], ba)
			ind += length
		} else if extra[ind] == 0x18 {
			// Thorchain memo data
			var length = int(extra[ind+1])
			if len(extra)-ind <= length {
				return nil, fmt.Errorf("thorchain memo data has insufficient length")
			}
			var ba = make([]byte, length)
			if length > 127 {
				ba = extra[ind+3 : ind+3+length]
			} else {
				ba = extra[ind+2 : ind+2+length]
			}
			parsedTxExtra[0x18] = append(parsedTxExtra[0x18], ba)
			ind += length
		}
	}

	return parsedTxExtra, nil
}
