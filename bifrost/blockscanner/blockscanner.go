package blockscanner

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	btypes "gitlab.com/thorchain/thornode/bifrost/blockscanner/types"
	"gitlab.com/thorchain/thornode/bifrost/config"
	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	"gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/constants"
)

type BlockScannerFetcher interface {
	FetchMemPool(height int64) (types.TxIn, error)
	FetchTxs(height int64) (types.TxIn, error)
	GetHeight() (int64, error)
}

type Block struct {
	Height int64
	Txs    []string
}

// BlockScanner is used to discover block height
type BlockScanner struct {
	cfg             config.BlockScannerConfiguration
	logger          zerolog.Logger
	wg              *sync.WaitGroup
	scanChan        chan int64
	stopChan        chan struct{}
	scannerStorage  ScannerStorage
	metrics         *metrics.Metrics
	previousBlock   int64
	globalTxsQueue  chan types.TxIn
	errorCounter    *prometheus.CounterVec
	thorchainBridge *thorclient.ThorchainBridge
	chainScanner    BlockScannerFetcher
}

// NewBlockScanner create a new instance of BlockScanner
func NewBlockScanner(cfg config.BlockScannerConfiguration, scannerStorage ScannerStorage, m *metrics.Metrics, thorchainBridge *thorclient.ThorchainBridge, chainScanner BlockScannerFetcher) (*BlockScanner, error) {
	var err error
	if scannerStorage == nil {
		return nil, errors.New("scannerStorage is nil")
	}
	if m == nil {
		return nil, errors.New("metrics instance is nil")
	}
	if thorchainBridge == nil {
		return nil, errors.New("thorchain bridge is nil")
	}

	logger := log.Logger.With().Str("module", "blockscanner").Str("chain", cfg.ChainID.String()).Logger()
	scanner := &BlockScanner{
		cfg:             cfg,
		logger:          logger,
		wg:              &sync.WaitGroup{},
		stopChan:        make(chan struct{}),
		scanChan:        make(chan int64),
		scannerStorage:  scannerStorage,
		metrics:         m,
		errorCounter:    m.GetCounterVec(metrics.CommonBlockScannerError),
		thorchainBridge: thorchainBridge,
		chainScanner:    chainScanner,
	}

	scanner.previousBlock, err = scanner.FetchLastHeight()
	return scanner, err
}

// GetMessages return the channel
func (b *BlockScanner) GetMessages() <-chan int64 {
	return b.scanChan
}

// Start block scanner
func (b *BlockScanner) Start(globalTxsQueue chan types.TxIn) {
	b.globalTxsQueue = globalTxsQueue
	b.wg.Add(1)
	go b.scanBlocks()
}

// scanBlocks
func (b *BlockScanner) scanBlocks() {
	b.logger.Debug().Msg("start to scan blocks")
	defer b.logger.Debug().Msg("stop scan blocks")
	defer b.wg.Done()
	currentPos, err := b.scannerStorage.GetScanPos()
	if err != nil {
		b.logger.Error().Err(err).Msgf("fail to get current block scan pos, %s will start from %d", b.cfg.ChainID, b.previousBlock)
	} else if currentPos > b.previousBlock {
		b.previousBlock = currentPos
	}

	lastMimirCheck := time.Now().Add(-constants.ThorchainBlockTime)
	haltHeight := int64(0)

	// start up to grab those blocks
	for {
		select {
		case <-b.stopChan:
			return
		default:
			currentBlock := b.previousBlock + 1

			// check if mimir has disabled this chain
			if time.Now().Sub(lastMimirCheck).Nanoseconds() >= constants.ThorchainBlockTime.Nanoseconds() {
				haltHeight, err = b.thorchainBridge.GetMimir(fmt.Sprintf("Halt%sChain", b.cfg.ChainID))
				if err != nil {
					b.logger.Error().Err(err).Msg("fail to get mimir setting")
				}
				lastMimirCheck = time.Now()
			}
			if haltHeight > 0 && currentBlock > haltHeight {
				time.Sleep(constants.ThorchainBlockTime)
				continue
			}
			txInMemPool, err := b.chainScanner.FetchMemPool(currentBlock)
			if err != nil {
				b.logger.Error().Err(err).Msg("fail to fetch MemPool")
			}
			if len(txInMemPool.TxArray) > 0 {
				select {
				case <-b.stopChan:
					return
				case b.globalTxsQueue <- txInMemPool:
				}
			}
			b.logger.Debug().Int64("block height", currentBlock).Msg("fetch txs")
			txIn, err := b.chainScanner.FetchTxs(currentBlock)
			if err != nil {
				// don't log an error if its because the block doesn't exist yet
				if !errors.Is(err, btypes.UnavailableBlock) {
					b.logger.Error().Err(err).Int64("block height", currentBlock).Msg("fail to get RPCBlock")
				}
				time.Sleep(b.cfg.BlockHeightDiscoverBackoff)
				continue
			}

			// enable this one , so we could see how far it is behind
			if currentBlock%100 == 0 {
				b.logger.Info().Int64("block height", currentBlock).Int("txs", len(txIn.TxArray))
			}
			b.previousBlock++
			b.metrics.GetCounter(metrics.TotalBlockScanned).Inc()
			if len(txIn.TxArray) > 0 {
				select {
				case <-b.stopChan:
					return
				case b.globalTxsQueue <- txIn:
				}
			}
			if err := b.scannerStorage.SetScanPos(b.previousBlock); err != nil {
				b.logger.Error().Err(err).Msg("fail to save block scan pos")
				// alert!!
				continue
			}
		}
	}
}

// FetchLastHeight retrieves the last height to start scanning blocks from on startup
// 1. Check if we have a height specified in config AND
//    its higher than the block scanner storage one, use that
// 2. Get the last observed height from THORChain if available
// 3. Use block scanner storage if > 0
// 4. Fetch last height from the chain itself
func (b *BlockScanner) FetchLastHeight() (int64, error) {
	// get scanner storage height
	currentPos, _ := b.scannerStorage.GetScanPos() // ignore error

	// 1. if we've configured a starting height, use that
	if b.cfg.StartBlockHeight > 0 && b.cfg.StartBlockHeight > currentPos {
		return b.cfg.StartBlockHeight, nil
	}
	// 2. attempt to find the height from thorchain
	// wait for thorchain to be caught up first
	if err := b.thorchainBridge.WaitToCatchUp(); err != nil {
		return 0, err
	}
	if b.thorchainBridge != nil {
		var height int64
		if b.cfg.ChainID.Equals(common.THORChain) {
			height, _ = b.thorchainBridge.GetBlockHeight()
		} else {
			height, _ = b.thorchainBridge.GetLastObservedInHeight(b.cfg.ChainID)
		}
		if height > 0 {
			return height, nil
		}
	}

	// 3. If we've already started scanning, begin where we left off
	if currentPos > 0 {
		return currentPos, nil
	}

	// 4. Start from latest height on the chain itself
	return b.chainScanner.GetHeight()
}

func (b *BlockScanner) Stop() {
	b.logger.Debug().Msg("receive stop request")
	defer b.logger.Debug().Msg("common block scanner stopped")
	close(b.stopChan)
	b.wg.Wait()
}
