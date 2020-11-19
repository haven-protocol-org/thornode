package bitcoin

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ctypes "github.com/binance-chain/go-sdk/common/types"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/cosmos/cosmos-sdk/client/keys"
	cKeys "github.com/cosmos/cosmos-sdk/crypto/keys"
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/thornode/bifrost/config"
	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	"gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	ttypes "gitlab.com/thorchain/thornode/x/thorchain/types"
)

func TestPackage(t *testing.T) { TestingT(t) }

type BitcoinSuite struct {
	client *Client
	server *httptest.Server
	bridge *thorclient.ThorchainBridge
	cfg    config.ChainConfiguration
	m      *metrics.Metrics
}

var _ = Suite(
	&BitcoinSuite{},
)

var m *metrics.Metrics

func GetMetricForTest(c *C) *metrics.Metrics {
	if m == nil {
		var err error
		m, err = metrics.NewMetrics(config.MetricsConfiguration{
			Enabled:      false,
			ListenPort:   9000,
			ReadTimeout:  time.Second,
			WriteTimeout: time.Second,
			Chains:       common.Chains{common.ETHChain},
		})
		c.Assert(m, NotNil)
		c.Assert(err, IsNil)
	}
	return m
}

func (s *BitcoinSuite) SetUpTest(c *C) {
	s.m = GetMetricForTest(c)
	s.cfg = config.ChainConfiguration{
		ChainID:     "BTC",
		UserName:    "bob",
		Password:    "password",
		DisableTLS:  true,
		HTTPostMode: true,
		BlockScanner: config.BlockScannerConfiguration{
			StartBlockHeight: 1, // avoids querying thorchain for block height
		},
	}
	ns := strconv.Itoa(time.Now().Nanosecond())
	ttypes.SetupConfigForTest()
	ctypes.Network = ctypes.TestNetwork
	c.Assert(os.Setenv("NET", "testnet"), IsNil)

	thordir := filepath.Join(os.TempDir(), ns, ".thorcli")
	cfg := config.ClientConfiguration{
		ChainID:         "thorchain",
		ChainHost:       "localhost",
		SignerName:      "bob",
		SignerPasswd:    "password",
		ChainHomeFolder: thordir,
	}

	kb := keys.NewInMemoryKeyBase()
	info, _, err := kb.CreateMnemonic(cfg.SignerName, cKeys.English, cfg.SignerPasswd, cKeys.Secp256k1)
	c.Assert(err, IsNil)
	thorKeys := thorclient.NewKeysWithKeybase(kb, info, cfg.SignerPasswd)
	c.Assert(err, IsNil)

	s.server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.RequestURI == "/" {
			r := struct {
				Method string   `json:"method"`
				Params []string `json:"params"`
			}{}
			json.NewDecoder(req.Body).Decode(&r)

			switch {
			case r.Method == "getblockhash":
				httpTestHandler(c, rw, "../../../../test/fixtures/btc/blockhash.json")
			case r.Method == "getblock":
				httpTestHandler(c, rw, "../../../../test/fixtures/btc/block_verbose.json")
			case r.Method == "gettransaction":
				if r.Params[0] == "27de3e1865c098cd4fded71bae1e8236fd27ce5dce6e524a9ac5cd1a17b5c241" {
					httpTestHandler(c, rw, "../../../../test/fixtures/btc/tx-c241.json")
				}
			case r.Method == "getrawtransaction":
				if r.Params[0] == "5b0876dcc027d2f0c671fc250460ee388df39697c3ff082007b6ddd9cb9a7513" {
					httpTestHandler(c, rw, "../../../../test/fixtures/btc/tx-5b08.json")
				} else if r.Params[0] == "54ef2f4679fb90af42e8d963a5d85645d0fd86e5fe8ea4e69dbf2d444cb26528" {
					httpTestHandler(c, rw, "../../../../test/fixtures/btc/tx-54ef.json")
				} else {
					httpTestHandler(c, rw, "../../../../test/fixtures/btc/tx.json")
				}
			case r.Method == "getblockcount":
				httpTestHandler(c, rw, "../../../../test/fixtures/btc/blockcount.json")
			case r.Method == "importaddress":
				httpTestHandler(c, rw, "../../../../test/fixtures/btc/importaddress.json")
			case r.Method == "listunspent":
				httpTestHandler(c, rw, "../../../../test/fixtures/btc/listunspent.json")
			case r.Method == "getrawmempool":
				httpTestHandler(c, rw, "../../../../test/fixtures/btc/getrawmempool.json")
			case r.Method == "getblockstats":
				httpTestHandler(c, rw, "../../../../test/fixtures/btc/blockstats.json")
			}
		} else if strings.HasPrefix(req.RequestURI, "/thorchain/nodeaccount/") {
			httpTestHandler(c, rw, "../../../../test/fixtures/endpoints/nodeaccount/template.json")
		} else if req.RequestURI == "/thorchain/lastblock" {
			httpTestHandler(c, rw, "../../../../test/fixtures/endpoints/lastblock/btc.json")
		} else if strings.HasPrefix(req.RequestURI, "/auth/accounts/") {
			_, err := rw.Write([]byte(`{ "jsonrpc": "2.0", "id": "", "result": { "height": "0", "result": { "value": { "account_number": "0", "sequence": "0" } } } }`))
			c.Assert(err, IsNil)
		} else if req.RequestURI == "/txs" {
			_, err := rw.Write([]byte(`{"height": "1", "txhash": "AAAA000000000000000000000000000000000000000000000000000000000000", "logs": [{"success": "true", "log": ""}]}`))
			c.Assert(err, IsNil)
		}
	}))
	cfg.ChainHost = s.server.Listener.Addr().String()
	s.bridge, err = thorclient.NewThorchainBridge(cfg, s.m, thorKeys)
	c.Assert(err, IsNil)
	s.cfg.RPCHost = s.server.Listener.Addr().String()
	s.client, err = NewClient(thorKeys, s.cfg, nil, s.bridge, s.m)
	c.Assert(err, IsNil)
	c.Assert(s.client, NotNil)
}

func (s *BitcoinSuite) TearDownTest(c *C) {
	s.server.Close()
}

func httpTestHandler(c *C, rw http.ResponseWriter, fixture string) {
	content, err := ioutil.ReadFile(fixture)
	if err != nil {
		c.Fatal(err)
	}
	rw.Header().Set("Content-Type", "application/json")
	if _, err := rw.Write(content); err != nil {
		c.Fatal(err)
	}
}

func (s *BitcoinSuite) TestGetBlock(c *C) {
	block, err := s.client.getBlock(1696761)
	c.Assert(err, IsNil)
	c.Assert(block.Hash, Equals, "000000008de7a25f64f9780b6c894016d2c63716a89f7c9e704ebb7e8377a0c8")
	c.Assert(block.Tx[0].Txid, Equals, "31f8699ce9028e9cd37f8a6d58a79e614a96e3fdd0f58be5fc36d2d95484716f")
	c.Assert(len(block.Tx), Equals, 110)
}

func (s *BitcoinSuite) TestFetchTxs(c *C) {
	txs, err := s.client.FetchTxs(0)
	c.Assert(err, IsNil)
	c.Assert(txs.Chain, Equals, common.BTCChain)
	c.Assert(txs.Count, Equals, "105")
	c.Assert(txs.TxArray[0].BlockHeight, Equals, int64(1696761))
	c.Assert(txs.TxArray[0].Tx, Equals, "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2")
	c.Assert(txs.TxArray[0].Sender, Equals, "tb1qdxxlx4r4jk63cve3rjpj428m26xcukjn5yegff")
	c.Assert(txs.TxArray[0].To, Equals, "mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB")
	c.Assert(txs.TxArray[0].Coins.Equals(common.Coins{common.NewCoin(common.BTCAsset, cosmos.NewUint(10000000))}), Equals, true)
	c.Assert(txs.TxArray[0].Gas.Equals(common.Gas{common.NewCoin(common.BTCAsset, cosmos.NewUint(22705334))}), Equals, true)
	c.Assert(len(txs.TxArray), Equals, 105)
}

func (s *BitcoinSuite) TestGetSender(c *C) {
	tx := btcjson.TxRawResult{
		Vin: []btcjson.Vin{
			{
				Txid: "31f8699ce9028e9cd37f8a6d58a79e614a96e3fdd0f58be5fc36d2d95484716f",
				Vout: 0,
			},
		},
	}
	sender, err := s.client.getSender(&tx)
	c.Assert(err, IsNil)
	c.Assert(sender, Equals, "n3jYBjCzgGNydQwf83Hz6GBzGBhMkKfgL1")

	tx.Vin[0].Vout = 1
	sender, err = s.client.getSender(&tx)
	c.Assert(err, IsNil)
	c.Assert(sender, Equals, "tb1qdxxlx4r4jk63cve3rjpj428m26xcukjn5yegff")
}

func (s *BitcoinSuite) TestGetMemo(c *C) {
	tx := btcjson.TxRawResult{
		Vout: []btcjson.Vout{
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm:       "OP_RETURN 74686f72636861696e3a636f6e736f6c6964617465",
					Hex:       "",
					ReqSigs:   0,
					Type:      "nulldata",
					Addresses: nil,
				},
			},
		},
	}
	memo, err := s.client.getMemo(&tx)
	c.Assert(err, IsNil)
	c.Assert(memo, Equals, "thorchain:consolidate")

	tx = btcjson.TxRawResult{
		Vout: []btcjson.Vout{
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm:  "OP_RETURN 737761703a6574682e3078633534633135313236393646334541373935366264396144343130383138654563414443466666663a30786335346331353132363936463345413739353662643961443431",
					Type: "nulldata",
				},
			},
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm:  "OP_RETURN 30383138654563414443466666663a3130303030303030303030",
					Type: "nulldata",
				},
			},
		},
	}
	memo, err = s.client.getMemo(&tx)
	c.Assert(err, IsNil)
	c.Assert(memo, Equals, "swap:eth.0xc54c1512696F3EA7956bd9aD410818eEcADCFfff:0xc54c1512696F3EA7956bd9aD410818eEcADCFfff:10000000000")

	tx = btcjson.TxRawResult{
		Vout: []btcjson.Vout{},
	}
	memo, err = s.client.getMemo(&tx)
	c.Assert(err, IsNil)
	c.Assert(memo, Equals, "")
}

func (s *BitcoinSuite) TestIgnoreTx(c *C) {
	// valid tx that will NOT be ignored
	tx := btcjson.TxRawResult{
		Vin: []btcjson.Vin{
			{
				Txid: "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Vout: 0,
			},
		},
		Vout: []btcjson.Vout{
			{
				Value: 0.12345678,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6"},
				},
			},
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm:       "OP_RETURN 74686f72636861696e3a636f6e736f6c6964617465",
					Addresses: []string{"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6"},
					Type:      "nulldata",
				},
			},
		},
	}
	ignored := s.client.ignoreTx(&tx)
	c.Assert(ignored, Equals, false)

	// invalid tx missing Vout
	tx = btcjson.TxRawResult{
		Vin: []btcjson.Vin{
			{
				Txid: "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Vout: 0,
			},
		},
		Vout: []btcjson.Vout{},
	}
	ignored = s.client.ignoreTx(&tx)
	c.Assert(ignored, Equals, true)

	// invalid tx missing vout[0].Value == no coins
	tx = btcjson.TxRawResult{
		Vin: []btcjson.Vin{
			{
				Txid: "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Vout: 0,
			},
		},
		Vout: []btcjson.Vout{
			{
				Value: 0,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6"},
				},
			},
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm: "OP_RETURN 74686f72636861696e3a636f6e736f6c6964617465",
				},
			},
		},
	}
	ignored = s.client.ignoreTx(&tx)
	c.Assert(ignored, Equals, true)

	// invalid tx missing vin[0].Txid means coinbase
	tx = btcjson.TxRawResult{
		Vin: []btcjson.Vin{
			{
				Txid: "",
				Vout: 0,
			},
		},
		Vout: []btcjson.Vout{
			{
				Value: 0.1234565,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6"},
				},
			},
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm: "OP_RETURN 74686f72636861696e3a636f6e736f6c6964617465",
				},
			},
		},
	}
	ignored = s.client.ignoreTx(&tx)
	c.Assert(ignored, Equals, true)

	// invalid tx missing vin
	tx = btcjson.TxRawResult{
		Vin: []btcjson.Vin{},
		Vout: []btcjson.Vout{
			{
				Value: 0.1234565,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6"},
				},
			},
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm: "OP_RETURN 74686f72636861696e3a636f6e736f6c6964617465",
				},
			},
		},
	}
	ignored = s.client.ignoreTx(&tx)
	c.Assert(ignored, Equals, true)

	// invalid tx multiple vout[0].Addresses
	tx = btcjson.TxRawResult{
		Vin: []btcjson.Vin{
			{
				Txid: "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Vout: 0,
			},
		},
		Vout: []btcjson.Vout{
			{
				Value: 0.1234565,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{
						"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6",
						"bc1q0s4mg25tu6termrk8egltfyme4q7sg3h0e56p3",
					},
				},
			},
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm: "OP_RETURN 74686f72636861696e3a636f6e736f6c6964617465",
				},
			},
		},
	}
	ignored = s.client.ignoreTx(&tx)
	c.Assert(ignored, Equals, true)

	// invalid tx > 2 vout with coins we only expect 2 max
	tx = btcjson.TxRawResult{
		Vin: []btcjson.Vin{
			{
				Txid: "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Vout: 0,
			},
		},
		Vout: []btcjson.Vout{
			{
				Value: 0.1234565,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{
						"bc1q0s4mg25tu6termrk8egltfyme4q7sg3h0e56p3",
					},
				},
			},
			{
				Value: 0.1234565,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{
						"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6",
					},
				},
			},
			{
				Value: 0.1234565,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{
						"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6",
					},
				},
			},
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm: "OP_RETURN 74686f72636861696e3a636f6e736f6c6964617465",
				},
			},
		},
	}
	ignored = s.client.ignoreTx(&tx)
	c.Assert(ignored, Equals, true)

	// valid tx == 2 vout with coins, 1 to vault, 1 with change back to user
	tx = btcjson.TxRawResult{
		Vin: []btcjson.Vin{
			{
				Txid: "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Vout: 0,
			},
		},
		Vout: []btcjson.Vout{
			{
				Value: 0.1234565,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{
						"bc1q0s4mg25tu6termrk8egltfyme4q7sg3h0e56p3",
					},
				},
			},
			{
				Value: 0.1234565,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{
						"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6",
					},
				},
			},
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm: "OP_RETURN 74686f72636861696e3a636f6e736f6c6964617465",
				},
			},
		},
	}
	ignored = s.client.ignoreTx(&tx)
	c.Assert(ignored, Equals, false)
}

func (s *BitcoinSuite) TestGetGas(c *C) {
	// vin[0] returns value 0.19590108
	tx := btcjson.TxRawResult{
		Vin: []btcjson.Vin{
			{
				Txid: "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Vout: 0,
			},
		},
		Vout: []btcjson.Vout{
			{
				Value: 0.12345678,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6"},
				},
			},
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm: "OP_RETURN 74686f72636861696e3a636f6e736f6c6964617465",
				},
			},
		},
	}
	gas, err := s.client.getGas(&tx)
	c.Assert(err, IsNil)
	c.Assert(gas.Equals(common.Gas{common.NewCoin(common.BTCAsset, cosmos.NewUint(7244430))}), Equals, true)

	tx = btcjson.TxRawResult{
		Vin: []btcjson.Vin{
			{
				Txid: "5b0876dcc027d2f0c671fc250460ee388df39697c3ff082007b6ddd9cb9a7513",
				Vout: 1,
			},
		},
		Vout: []btcjson.Vout{
			{
				Value: 0.00195384,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6"},
				},
			},
			{
				Value: 1.49655603,
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Addresses: []string{"tb1qkq7weysjn6ljc2ywmjmwp8ttcckg8yyxjdz5k6"},
				},
			},
			{
				ScriptPubKey: btcjson.ScriptPubKeyResult{
					Asm: "OP_RETURN 74686f72636861696e3a636f6e736f6c6964617465",
				},
			},
		},
	}
	gas, err = s.client.getGas(&tx)
	c.Assert(err, IsNil)
	c.Assert(gas.Equals(common.Gas{common.NewCoin(common.BTCAsset, cosmos.NewUint(149013))}), Equals, true)
}

func (s *BitcoinSuite) TestGetChain(c *C) {
	chain := s.client.GetChain()
	c.Assert(chain, Equals, common.BTCChain)
}

func (s *BitcoinSuite) TestGetAddress(c *C) {
	os.Setenv("NET", "mainnet")
	pubkey := common.PubKey("tthorpub1addwnpepqt7qug8vk9r3saw8n4r803ydj2g3dqwx0mvq5akhnze86fc536xcycgtrnv")
	addr := s.client.GetAddress(pubkey)
	c.Assert(addr, Equals, "bc1q2gjc0rnhy4nrxvuklk6ptwkcs9kcr59mcl2q9j")
}

func (s *BitcoinSuite) TestGetHeight(c *C) {
	height, err := s.client.GetHeight()
	c.Assert(err, IsNil)
	c.Assert(height, Equals, int64(10))
}

func (s *BitcoinSuite) TestGetAccount(c *C) {
	acct, err := s.client.GetAccount("tthorpub1addwnpepqt7qug8vk9r3saw8n4r803ydj2g3dqwx0mvq5akhnze86fc536xcycgtrnv")
	c.Assert(err, IsNil)
	c.Assert(acct.AccountNumber, Equals, int64(0))
	c.Assert(acct.Sequence, Equals, int64(0))
	c.Assert(acct.Coins[0].Amount, Equals, uint64(2502000000))

	acct1, err := s.client.GetAccount("")
	c.Assert(err, NotNil)
	c.Assert(acct1.AccountNumber, Equals, int64(0))
	c.Assert(acct1.Sequence, Equals, int64(0))
	c.Assert(acct1.Coins, HasLen, 0)
}

func (s *BitcoinSuite) TestOnObservedTxIn(c *C) {
	pkey := ttypes.GetRandomPubKey()
	txIn := types.TxIn{
		Count: "1",
		Chain: common.BTCChain,
		TxArray: []types.TxInItem{
			{
				BlockHeight: 1,
				Tx:          "31f8699ce9028e9cd37f8a6d58a79e614a96e3fdd0f58be5fc36d2d95484716f",
				Sender:      "bc1q2gjc0rnhy4nrxvuklk6ptwkcs9kcr59mcl2q9j",
				To:          "bc1q0s4mg25tu6termrk8egltfyme4q7sg3h0e56p3",
				Coins: common.Coins{
					common.NewCoin(common.BTCAsset, cosmos.NewUint(123456789)),
				},
				Memo:                "MEMO",
				ObservedVaultPubKey: pkey,
			},
		},
	}
	blockMeta := NewBlockMeta("000000001ab8a8484eb89f04b87d90eb88e2cbb2829e84eb36b966dcb28af90b", 1, "00000000ffa57c95f4f226f751114e9b24fdf8dbe2dbc02a860da9320bebd63e")
	c.Assert(s.client.blockMetaAccessor.SaveBlockMeta(blockMeta.Height, blockMeta), IsNil)
	s.client.OnObservedTxIn(txIn.TxArray[0], 1)
	blockMeta, err := s.client.blockMetaAccessor.GetBlockMeta(1)
	c.Assert(err, IsNil)
	c.Assert(blockMeta, NotNil)

	txIn = types.TxIn{
		Count: "1",
		Chain: common.BTCChain,
		TxArray: []types.TxInItem{
			{
				BlockHeight: 2,
				Tx:          "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Sender:      "bc1q0s4mg25tu6termrk8egltfyme4q7sg3h0e56p3",
				To:          "bc1q2gjc0rnhy4nrxvuklk6ptwkcs9kcr59mcl2q9j",
				Coins: common.Coins{
					common.NewCoin(common.BTCAsset, cosmos.NewUint(123456)),
				},
				Memo:                "MEMO",
				ObservedVaultPubKey: pkey,
			},
		},
	}
	blockMeta = NewBlockMeta("000000001ab8a8484eb89f04b87d90eb88e2cbb2829e84eb36b966dcb28af90b", 2, "00000000ffa57c95f4f226f751114e9b24fdf8dbe2dbc02a860da9320bebd63e")
	c.Assert(s.client.blockMetaAccessor.SaveBlockMeta(blockMeta.Height, blockMeta), IsNil)
	s.client.OnObservedTxIn(txIn.TxArray[0], 2)
	blockMeta, err = s.client.blockMetaAccessor.GetBlockMeta(2)
	c.Assert(err, IsNil)
	c.Assert(blockMeta, NotNil)

	txIn = types.TxIn{
		Count: "2",
		Chain: common.BTCChain,
		TxArray: []types.TxInItem{
			{
				BlockHeight: 3,
				Tx:          "44ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Sender:      "bc1q0s4mg25tu6termrk8egltfyme4q7sg3h0e56p3",
				To:          "bc1q2gjc0rnhy4nrxvuklk6ptwkcs9kcr59mcl2q9j",
				Coins: common.Coins{
					common.NewCoin(common.BTCAsset, cosmos.NewUint(12345678)),
				},
				Memo:                "MEMO",
				ObservedVaultPubKey: pkey,
			},
			{
				BlockHeight: 3,
				Tx:          "54ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Sender:      "bc1q0s4mg25tu6termrk8egltfyme4q7sg3h0e56p3",
				To:          "bc1q2gjc0rnhy4nrxvuklk6ptwkcs9kcr59mcl2q9j",
				Coins: common.Coins{
					common.NewCoin(common.BTCAsset, cosmos.NewUint(123456)),
				},
				Memo:                "MEMO",
				ObservedVaultPubKey: pkey,
			},
		},
	}
	blockMeta = NewBlockMeta("000000001ab8a8484eb89f04b87d90eb88e2cbb2829e84eb36b966dcb28af90b", 3, "00000000ffa57c95f4f226f751114e9b24fdf8dbe2dbc02a860da9320bebd63e")
	c.Assert(s.client.blockMetaAccessor.SaveBlockMeta(blockMeta.Height, blockMeta), IsNil)
	for _, item := range txIn.TxArray {
		s.client.OnObservedTxIn(item, 3)
	}

	blockMeta, err = s.client.blockMetaAccessor.GetBlockMeta(3)
	c.Assert(err, IsNil)
	c.Assert(blockMeta, NotNil)
}

func (s *BitcoinSuite) TestProcessReOrg(c *C) {
	// can't get previous block meta should not error
	var result btcjson.GetBlockVerboseTxResult
	blockContent, err := ioutil.ReadFile("../../../../test/fixtures/btc/block.json")
	c.Assert(err, IsNil)
	c.Assert(json.Unmarshal(blockContent, &result), IsNil)
	// should not trigger re-org process
	c.Assert(s.client.processReorg(&result), IsNil)

	// add one UTXO which will trigger the re-org process next
	previousHeight := result.Height - 1
	blockMeta := NewBlockMeta(ttypes.GetRandomTxHash().String(), previousHeight, ttypes.GetRandomTxHash().String())
	hash := "27de3e1865c098cd4fded71bae1e8236fd27ce5dce6e524a9ac5cd1a17b5c241"
	blockMeta.AddCustomerTransaction(hash)
	c.Assert(s.client.blockMetaAccessor.SaveBlockMeta(previousHeight, blockMeta), IsNil)
	s.client.globalErrataQueue = make(chan types.ErrataBlock, 1)
	c.Assert(s.client.processReorg(&result), IsNil)
	// make sure there is errata block in the queue
	c.Assert(s.client.globalErrataQueue, HasLen, 1)
	blockMeta, err = s.client.blockMetaAccessor.GetBlockMeta(previousHeight)
	c.Assert(err, IsNil)
	c.Assert(blockMeta, NotNil)
}

func (s *BitcoinSuite) TestGetMemPool(c *C) {
	txIns, err := s.client.getMemPool(1024)
	c.Assert(err, IsNil)
	c.Assert(txIns.TxArray, HasLen, 1)

	// process it again , the tx will be ignored
	txIns, err = s.client.getMemPool(1024)
	c.Assert(err, IsNil)
	c.Assert(txIns.TxArray, HasLen, 0)
}

func (s *BitcoinSuite) TestConfirmationCountReady(c *C) {
	c.Assert(s.client.ConfirmationCountReady(types.TxIn{
		Chain:    common.BTCChain,
		TxArray:  nil,
		Filtered: true,
		MemPool:  false,
	}), Equals, true)
	pkey := ttypes.GetRandomPubKey()
	c.Assert(s.client.ConfirmationCountReady(types.TxIn{
		Chain: common.BTCChain,
		TxArray: []types.TxInItem{
			{
				BlockHeight: 2,
				Tx:          "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Sender:      "bc1q0s4mg25tu6termrk8egltfyme4q7sg3h0e56p3",
				To:          "bc1q2gjc0rnhy4nrxvuklk6ptwkcs9kcr59mcl2q9j",
				Coins: common.Coins{
					common.NewCoin(common.BTCAsset, cosmos.NewUint(123456)),
				},
				Memo:                "MEMO",
				ObservedVaultPubKey: pkey,
			},
		},
		Filtered: true,
		MemPool:  true,
	}), Equals, true)

	c.Assert(s.client.ConfirmationCountReady(types.TxIn{
		Chain: common.BTCChain,
		TxArray: []types.TxInItem{
			{
				BlockHeight: 2,
				Tx:          "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Sender:      "bc1q0s4mg25tu6termrk8egltfyme4q7sg3h0e56p3",
				To:          "bc1q2gjc0rnhy4nrxvuklk6ptwkcs9kcr59mcl2q9j",
				Coins: common.Coins{
					common.NewCoin(common.BTCAsset, cosmos.NewUint(123456)),
				},
				Memo:                "MEMO",
				ObservedVaultPubKey: pkey,
			},
		},
		Filtered: true,
		MemPool:  false,
	}), Equals, true)

	c.Assert(s.client.ConfirmationCountReady(types.TxIn{
		Chain: common.BTCChain,
		TxArray: []types.TxInItem{
			{
				BlockHeight: 2,
				Tx:          "24ed2d26fd5d4e0e8fa86633e40faf1bdfc8d1903b1cd02855286312d48818a2",
				Sender:      "bc1q0s4mg25tu6termrk8egltfyme4q7sg3h0e56p3",
				To:          "bc1q2gjc0rnhy4nrxvuklk6ptwkcs9kcr59mcl2q9j",
				Coins: common.Coins{
					common.NewCoin(common.BTCAsset, cosmos.NewUint(12345600000)),
				},
				Gas: common.Gas{
					common.NewCoin(common.BTCAsset, cosmos.NewUint(40000)),
				},
				Memo:                "MEMO",
				ObservedVaultPubKey: pkey,
			},
		},
		Filtered: true,
		MemPool:  false,
	}), Equals, false)
}
