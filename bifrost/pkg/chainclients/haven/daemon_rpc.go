package haven

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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
	Difficulty                  uint64
	Difficulty_Top64            uint64
	Free_Space                  uint64
	Grey_Peerlist_Size          int
	Height                      int64 // use int64 instead of uint64 since thorchain uses int64(not to convert each time). Shouln't be a problem for a long time for haven anyways :)
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
	Difficulty    uint64
	Hash          string
	Height        int64
	Major_version int
	Minor_version int
	Nonce         uint64
	Num_txes      int
	Orphan_status bool
	Prev_Hash     string
	Reward        uint64
	Timestamp     uint64
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
	Amount      uint64
	Key_Offsets []uint64
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
	Amount uint64
	Target Target
}

type RctSignatures struct {
	Type                  int
	TxnFee                uint64
	TxnFee_Usd            uint64
	TxnFee_Xasset         uint64
	TxnOffshoreFee        uint64
	TxnOffshoreFee_Usd    uint64
	TxnOffshoreFee_Xasset uint64
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

var DaemonHost = ""
var WalletRPCHost = ""

func getChainInfo() (GetInfoResult, error) {

	var reply GetInfoResult

	// prepare body
	requestBody, err := json.Marshal(map[string]interface{}{"json_rpc": 2.0, "id": 0, "method": "get_info"})
	if err != nil {
		return reply, fmt.Errorf("getChainInfo() Marshaling request Error: %+v\n", err)
	}

	// execute request
	resp, err := http.Post("http://"+DaemonHost+":27750/json_rpc", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return reply, fmt.Errorf("getChainInfo() Http Error: %+v\n", err)
	}
	defer resp.Body.Close()

	// read and parse the returned response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return reply, fmt.Errorf("getChainInfo() Reading response Error: %+v\n", err)
	}
	err = json.Unmarshal(body, &reply)
	if err != nil {
		return reply, fmt.Errorf("getChainInfo() Unmarshaling Response Error: %+v\n", err)
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

func GetBlock(height int64) (Block, error) {

	var reply Block

	// prepare body
	params := map[string]int64{"height": height}
	requestBody, err := json.Marshal(map[string]interface{}{"json_rpc": 2.0, "id": 0, "method": "get_block", "params": params})
	if err != nil {
		return reply, fmt.Errorf("GetBlock() Marshaling request Error: %+v\n", err)
	}

	// execute request
	resp, err := http.Post("http://"+DaemonHost+":27750/json_rpc", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return reply, fmt.Errorf("GetBlock() Http Error: %+v\n", err)
	}
	defer resp.Body.Close()

	// read and parse the returned response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return reply, fmt.Errorf("GetBlock() Reading response Error: %+v\n", err)
	}
	err = json.Unmarshal(body, &reply)
	if err != nil {
		return reply, fmt.Errorf("GetBlock() Unmarshaling Response Error: %+v\n", err)
	}

	return reply, err
}

func GetTxes(txes []string) ([]RawTx, error) {

	requestBody, err := json.Marshal(map[string]interface{}{"txs_hashes": txes, "decode_as_json": true})
	if err != nil {
		return nil, fmt.Errorf("GetTxes() Marshaling request Error: %+v\n", err)
	}

	resp, err := http.Post("http://"+DaemonHost+":27750/get_transactions", "application/json", bytes.NewBuffer(requestBody))
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

	resp, err := http.Get("http://" + DaemonHost + ":27750/get_transaction_pool")
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

func SendRawTransaction(txHash string) BroadcastTxResponse {

	var reply BroadcastTxResponse

	requestBody, err := json.Marshal(map[string]interface{}{"tx_as_hex": txHash})
	if err != nil {
		reply.Status = "Marshaling Request Error"
		reply.Reason = fmt.Sprintf("%+v", err)
		return reply
	}

	resp, err := http.Post("http://"+DaemonHost+":27750/sendrawtransaction", "application/json", bytes.NewBuffer(requestBody))
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
