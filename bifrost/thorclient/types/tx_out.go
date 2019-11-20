package types

import "gitlab.com/thorchain/bepswap/thornode/common"

// TODO decomission TxArrayItem, in favor of TxOutItem in thornode
type TxArrayItem struct {
	Chain       common.Chain  `json:"chain"`
	To          string        `json:"to"`
	PoolAddress common.PubKey `json:"pool_address"`
	SeqNo       string        `json:"seq_no"`
	Coin        common.Coin   `json:"coin"`
	Memo        string        `json:"memo"`
	InHash      common.TxID   `json:"in_hash"`
	OutHash     common.TxID   `json:"out_hash"`
}
type TxOut struct {
	Height  string        `json:"height"`
	Hash    string        `json:"hash"`
	Chain   common.Chain  `json:"chain"`
	TxArray []TxArrayItem `json:"tx_array"`
}