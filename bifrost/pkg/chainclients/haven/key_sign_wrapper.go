package haven

import (
	"encoding/hex"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	moneroCryptoBase58 "github.com/haven-protocol-org/monero-go-utils/base58"
	moneroCrypto "github.com/haven-protocol-org/monero-go-utils/crypto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/thornode/bifrost/tss"
	"gitlab.com/thorchain/thornode/common"
)

// KeySignWrapper is a wrap of private key and also tss instance
// it also implement the txscript.Signable interface, and will decide which method to use based on the pubkey
type KeySignWrapper struct {
	privViewKey   [32]byte
	privSpendKey  [32]byte
	pubKey        common.PubKey
	tssKeyManager tss.ThorchainKeyManager
	logger        zerolog.Logger
}

// NewKeySignWrapper create a new instance of Keysign Wrapper
func NewKeySignWrapper(privViewKey [32]byte, privSpendKey [32]byte, pubKey common.PubKey, tssKeyManager tss.ThorchainKeyManager) (*KeySignWrapper, error) {
	return &KeySignWrapper{
		privViewKey:   privViewKey,
		privSpendKey:  privSpendKey,
		pubKey:        pubKey,
		tssKeyManager: tssKeyManager,
		logger:        log.Logger.With().Str("module", "keysign_wrapper").Logger(),
	}, nil
}

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

func generateHavenWallet(privViewKey *[32]byte, privSpendKey *[32]byte, pubKey common.PubKey, walletName string, password string) ([32]byte, [32]byte, string, error) {
	// generate pubKeys to return to client
	// TODO: might be able to remove this. We don't really need to keep these public keys
	var pubSpendKey [32]byte
	moneroCrypto.PublicFromSecret(&pubSpendKey, privSpendKey)
	var pubViewKey [32]byte
	moneroCrypto.PublicFromSecret(&pubViewKey, privViewKey)

	// get address
	// walletAddr, err := pubKey.GetAddress(common.XHVChain)
	// if err != nil {
	// 	return pubSpendKey, pubSpendKey, "", err
	// }

	// generate the walletAddr. Normally we would just the code commented out above. but pubKey.GetAddress is still not implemented yet.
	var addData []byte
	addData = append(addData, pubSpendKey[:]...)
	addData = append(addData, pubViewKey[:]...)
	chainNetwork := common.GetCurrentChainNetwork()
	var tag uint64
	switch chainNetwork {
	case common.MockNet:
		// Haven testnet tag
		tag = 0x59f4
	case common.TestNet:
		// Haven testnet tag
		tag = 0x59f4
	case common.MainNet:
		// Haven mainnet tag
		tag = 0x05af4
	}
	walletAddr := moneroCryptoBase58.EncodeAddr(tag, addData)
	////////////////////////////////

	// create the wallet
	err := CreateWallet(walletName, walletAddr, hex.EncodeToString(privSpendKey[:]), hex.EncodeToString(privViewKey[:]), password, false)
	if err != nil {
		return pubSpendKey, pubSpendKey, walletAddr, err
	} else {
		return pubSpendKey, pubViewKey, walletAddr, nil
	}
}

func loginToWallet(walletName string, password string) bool {
	return OpenWallet(walletName, password)
}

// GetSignable based on the given poolPubKey
func (w *KeySignWrapper) GetSignable(poolPubKey common.PubKey) TssSignable {
	// s, err := NewTssSignable(poolPubKey, w.tssKeyManager, w.keySignPartyMgr)
	// if err != nil {
	// 	w.logger.Err(err).Msg("fail to create tss signable")
	// 	return nil
	// }
	return TssSignable{}
}
