package haven

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/rpc"

	"github.com/powerman/rpc-codec/jsonrpc2"
)

type GetInfoResult struct {
	Alt_Blocks_Count            int
	Bloc_Size_Limit             uint
	Block_Size_Median           uint
	Block_Weight_Limit          uint
	Block_Weight_Median         uint
	Bootstrap_Daemon_Address    string
	Cumulative_Difficulty       int
	Cumulative_Difficulty_Top64 int
	Database_Size               int
	Difficulty                  int64
	Difficulty_Top64            int64
	Free_Space                  int64
	Grey_Peerlist_Size          int
	Height                      int64
	Height_Without_Bootstrap    uint64
	Incoming_Connections_Count  int
	Mainnet                     bool
	Nettype                     string
	Offline                     bool
	Outgoing_Connections_Count  int
	Rpc_Connections_Count       int
	Stagenet                    bool
	Start_Time                  int
	Status                      string
	Target                      int
	Target_Height               int
	Testnet                     bool
	Top_Block_Hash              string
	Tx_Count                    int
	Tx_Pool_Size                int
	Untrusted                   bool
	Update_Available            bool
	Version                     string
	Was_Bootstrap_Ever_Used     bool
	White_Peerlist_Size         int
	Wide_Cumulative_Difficulty  string
	Wide_Difficulty             string
}

type BlockHeader struct {
	Block_Size    int
	Depth         int
	Difficulty    int64
	Hash          string
	Height        int64
	Major_version int
	Minor_version int
	Nonce         int64
	Num_txes      int
	Orphan_status bool
	Prev_Hash     string
	Reward        int64
	Timestamp     int64
}

type Block struct {
	Blob          string
	Block_Header  BlockHeader
	Json          string
	Miner_Tx_Hash string
	Status        string
	Untrusted     bool
	Tx_Hashes     []string
}

type VinKey struct {
	Amount      int64
	Key_Offsets []int64
	K_Image     string
}

type VinEntry struct {
	Key      VinKey
	Onshore  VinKey
	Offshore VinKey
}

type Target struct {
	Key        string
	Offshore   string
	Xasset     string
	asset_type string
}

type VoutEntry struct {
	Amount int64
	Target Target
}

type RctSignatures struct {
	Type                  int
	TxnFee                int64
	TxnFee_Usd            int64
	TxnFee_Xasset         int64
	TxnOffshoreFee        int64
	TxnOffshoreFee_Usd    int64
	TxnOffshoreFee_Xasset int64
	EcdhInfo              []map[string]string
	OutPk                 []string
	OutPk_Usd             []string
	OutPk_Xasset          []string
}

type RawTx struct {
	Hash           string
	Version        int
	Unlock_Time    int
	Vin            []VinEntry
	Vout           []VoutEntry
	Extra          []byte
	Rct_Signatures RctSignatures
	Block_Height   int64
}

type CreatedTx struct {
	Amount_List      []uint64
	Fee_List         []uint64
	Multisig_Txset   string
	Tx_Hash_List     []string
	Tx_Key_List      []string
	Unsigned_Txset   string
	Tx_Blob_List     []string
	Tx_Metadata_List []string
}

type BroadcastTxResponse struct {
	Credits             uint
	Double_Spend        bool
	Fee_Too_Low         bool
	Invalid_Input       bool
	Invalid_Output      bool
	Low_Mixin           bool
	Not_Relayed         bool
	Overspend           bool
	Reason              string
	Sanity_Check_Failed bool
	Status              string
	Too_Big             bool
	Too_Few_Outputs     bool
	Top_Hash            string
	Untrusted           bool
}

const IPAddress = "192.168.1.110"

func getChainInfo() (GetInfoResult, error) {
	// Connect to daemon RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://" + IPAddress + ":27750/json_rpc")
	defer clientHTTP.Close()

	var reply GetInfoResult
	var err error

	// Get Info
	err = clientHTTP.Call("get_info", nil, &reply)
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		return reply, fmt.Errorf("Failed to get chain Info: %+v\n", err)
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		return reply, fmt.Errorf("Failed to get chain Info: %+v\n", rpcerr)
	}

	return reply, nil
}

// GetHeight gets the height of the haven blockchain
func GetHeight() (int64, error) {

	chainInfo, err := getChainInfo()
	if err != nil {
		return 0, fmt.Errorf("Failed to get chain height: %+v\n", err)
	}

	// daemon returns the height that is currently in process
	// What we actually need is the last height
	return chainInfo.Height - 1, nil
}

// GetVersion gets the version of the running haven daemon
func GetVersion() (string, error) {

	chainInfo, err := getChainInfo()
	if err != nil {
		return "", fmt.Errorf("Failed to get chain height: %+v\n", err)
	}

	return chainInfo.Version, nil
}

func GetBlock(height int64) (Block, jsonrpc2.Error) {

	// Connect to daemon RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://" + IPAddress + ":27750/json_rpc")
	defer clientHTTP.Close()

	req := map[string]int64{"height": height}

	var reply Block
	var rpcerr jsonrpc2.Error

	// Get Height
	err := clientHTTP.Call("get_block", req, &reply)
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		rpcerr.Message = "Connection is shutdown unexpectedly"
	} else if err != nil {
		rpcerr = *(jsonrpc2.ServerError(err))
	}

	return reply, rpcerr
}

func GetTxes(txes []string) ([]RawTx, error) {

	requestBody, err := json.Marshal(map[string]interface{}{"txs_hashes": txes, "decode_as_json": true})
	if err != nil {
		return nil, fmt.Errorf("GetTxes() Marshaling request Error: %+v\n", err)
	}

	resp, err := http.Post("http://"+IPAddress+":27750/get_transactions", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("GetTxes() Http Error: %+v\n", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GetTxes() Reading response Error: %+v\n", err)
	}

	type Tx struct {
		Block_Height int64
		Tx_Hash      string
	}

	type GetTxResult struct {
		Status      string
		Txs_As_Json []string
		Txs         []Tx
	}

	var txResult GetTxResult
	var rawTxs []RawTx

	// parse the returned resutl
	err = json.Unmarshal(body, &txResult)
	if err != nil {
		return nil, fmt.Errorf("GetTxes() Unmarshaling Response Error: %+v\n", err)
	}

	// parse each tx in the result and save
	for ind, jsonTx := range txResult.Txs_As_Json {
		var rawTx RawTx
		err := json.Unmarshal([]byte(jsonTx), &rawTx)
		if err != nil {
			return nil, fmt.Errorf("GetTxes() Unmarshaling Tx Error: %+v\n", err)
		}
		rawTx.Block_Height = txResult.Txs[ind].Block_Height
		rawTx.Hash = txResult.Txs[ind].Tx_Hash
		rawTxs = append(rawTxs, rawTx)
	}

	return rawTxs, err
}

func GetPoolTxs() ([]string, error) {

	resp, err := http.Get("http://" + IPAddress + ":27750/get_transaction_pool")
	if err != nil {
		return nil, fmt.Errorf("GetPoolTxs() Marshaling request Error: %+v\n", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GetPoolTxs() Reading response Error: %+v\n", err)
	}

	type Tx struct {
		Id_Hash string
	}

	type getPoolTxs struct {
		Transactions []Tx
	}

	var result getPoolTxs

	// parse the returned resutl
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("GetPoolTxs() Unmarshaling Response Error: %+v\n", err)
	}

	var txs = make([]string, 0)
	for _, tx := range result.Transactions {
		txs = append(txs, tx.Id_Hash)
	}

	return txs, nil
}

func CreateWallet(fileName string, address string, spendKey string, viewKey string, password string, autosave bool) error {

	// Connect to wallet RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://" + IPAddress + ":12345/json_rpc")
	defer clientHTTP.Close()

	req := map[string]interface{}{"filename": fileName, "address": address, "spendkey": spendKey, "viewkey": viewKey, "password": password, "autosave_current": autosave}

	type Reply struct {
		Address string
		Info    string
	}

	var reply Reply
	var err error

	// create wallet on rpc
	err = clientHTTP.Call("generate_from_keys", req, &reply)
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		return fmt.Errorf("RPC Error: %v\n", err)
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		return fmt.Errorf("RPC ServerError Error: %v\n", rpcerr)
	}

	return nil
}

func OpenWallet(walletName string, password string) bool {

	// Connect to wallet RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://" + IPAddress + ":12345/json_rpc")
	defer clientHTTP.Close()

	// create a request
	req := map[string]interface{}{"filename": walletName, "password": password}

	type Reply struct{}

	var reply Reply
	var err error

	// open wallet on rpc
	err = clientHTTP.Call("open_wallet", req, &reply)
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		fmt.Errorf("Failed to open wallet: %+v\n", err)
		return false
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		fmt.Errorf("Failed to open wallet: %+v\n", rpcerr)
		return false
	}

	return true
}

func CreateTx(dsts []map[string]interface{}, asset string, memo string) (CreatedTx, error) {

	// Connect to Wallet RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://" + IPAddress + ":12345/json_rpc")
	defer clientHTTP.Close()

	// create a request
	req := map[string]interface{}{
		"destinations":    dsts,
		"memo":            memo,
		"priority":        1,
		"ring_size":       11,
		"get_tx_keys":     true,
		"get_tx_hex":      true,
		"get_tx_metadata": true,
		"do_not_relay":    true,
		"asset_type":      asset,
	}

	var reply CreatedTx
	var err error

	// call the rpc method
	if asset == "XHV" {
		err = clientHTTP.Call("transfer_split", req, &reply)
	} else if asset == "XUSD" {
		err = clientHTTP.Call("offshore_transfer", req, &reply)
	} else {
		err = clientHTTP.Call("xasset_transfer", req, &reply)
	}

	// check for errors
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		return reply, fmt.Errorf("Failed to create tx: %+v\n", err)
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		return reply, fmt.Errorf("Failed to create tx: %+v\n", rpcerr)
	}

	return reply, nil
}

func SendRawTransaction(txHash string) BroadcastTxResponse {

	var reply BroadcastTxResponse

	requestBody, err := json.Marshal(map[string]interface{}{"tx_as_hex": txHash})
	if err != nil {
		reply.Status = "Marshaling Request Error"
		reply.Reason = fmt.Sprintf("%+v", err)
		return reply
	}

	resp, err := http.Post("http://"+IPAddress+":27750/sendrawtransaction", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		reply.Status = "Http Error"
		reply.Reason = fmt.Sprintf("%+v", err)
		return reply
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		reply.Status = "Read Error"
		reply.Reason = fmt.Sprintf("%+v", err)
		return reply
	}

	// parse the returned resutl
	err = json.Unmarshal(body, &reply)
	if err != nil {
		reply.Status = "Unmarshaling Response Error"
		reply.Reason = fmt.Sprintf("%+v", err)
		return reply
	}

	return reply
}
