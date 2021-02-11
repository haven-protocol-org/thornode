package haven

import (
	"fmt"

	"gitlab.com/thorchain/thornode/common"
)

// UnspentTransactionOutput struct
type UnspentTransactionOutput struct {
	// TODO: update this string to chainHash type
	TxID        string        `json:"tx_id"`
	N           uint32        `json:"n"`
	Value       float64       `json:"value"`
	BlockHeight int64         `json:"block_height"`
	VaultPubKey common.PubKey `json:"vault_pub_key"`
	Spent       bool          `json:"spent"`
}

// NewUnspentTransactionOutput create a new instance of UnspentTransactionOutput
func NewUnspentTransactionOutput(txID string, n uint32, value float64, blockHeight int64, vaultPubKey common.PubKey) UnspentTransactionOutput {
	return UnspentTransactionOutput{
		TxID:        txID,
		N:           n,
		Value:       value,
		BlockHeight: blockHeight,
		VaultPubKey: vaultPubKey,
		Spent:       false,
	}
}

// GetKey return a key
func (t UnspentTransactionOutput) GetKey() string {
	return fmt.Sprintf("%s:%d", t.TxID, t.N)
}
