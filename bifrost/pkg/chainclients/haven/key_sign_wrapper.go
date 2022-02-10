package haven

import (
	"encoding/hex"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	moneroCrypto "github.com/haven-protocol-org/monero-go-utils/crypto"
	"gitlab.com/thorchain/thornode/common"
)

// getHavenPrivateKey contructs a private key from a thorchain private key
func getHavenPrivateKey(key cryptotypes.PrivKey) ([32]byte, [32]byte) {
	// prepare seed
	h := moneroCrypto.NewHash()
	var keyHash [32]byte
	h.Write(key.Bytes())
	h.Sum(keyHash[:0])

	// generate the secret keys
	var secretSpendKey [32]byte
	var secretViewKey [32]byte
	moneroCrypto.SecretFromSeed(&secretSpendKey, &keyHash)
	moneroCrypto.ViewFromSpend(&secretViewKey, &secretSpendKey)
	return secretViewKey, secretSpendKey
}

func generateWalletAddress(privSpendKey *[32]byte, privViewKey *[32]byte) (common.Address, error) {
	// generate pubspendKey
	var pubSpendKey [32]byte
	moneroCrypto.PublicFromSecret(&pubSpendKey, privSpendKey)

	// generate the cryptonote data
	var cnData []byte
	cnData = append(cnData, privViewKey[:]...)
	cnData = append(cnData, pubSpendKey[:]...)
	walletAddr, err := common.PubKey(hex.EncodeToString(cnData)).GetAddress(common.XHVChain)
	return walletAddr, err
}
