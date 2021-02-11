package haven

import (
	"encoding/hex"
	"fmt"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/haven-protocol-org/monero-go-utils/base58"
	moneroCrypto "github.com/haven-protocol-org/monero-go-utils/crypto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
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

// NewKeysignWrapper create a new instance of Keysign Wrapper
func NewKeySignWrapper(privViewKey *[32]byte, privSpendKey *[32]byte, bridge *thorclient.ThorchainBridge, tssKeyManager tss.ThorchainKeyManager) (*KeySignWrapper, error) {
	pubKey, err := GetBech32AccountPubKey(privSpendKey)
	if err != nil {
		return nil, fmt.Errorf("fail to get the pubkey: %w", err)
	}
	return &KeySignWrapper{
		privViewKey:   *privViewKey,
		privSpendKey:  *privSpendKey,
		pubKey:        pubKey,
		tssKeyManager: tssKeyManager,
		logger:        log.Logger.With().Str("module", "keysign_wrapper").Logger(),
	}, nil
}

// GetBech32AccountPubKey calculate the pubkey given private key
func GetBech32AccountPubKey(key *[32]byte) (common.PubKey, error) {
	var buf [32]byte
	moneroCrypto.PublicFromSecret(&buf, key)
	pk := secp256k1.PubKey(buf[:])
	return common.NewPubKeyFromCrypto(pk)
}

// getHavenPrivateKey contructs a private key from a thorchain private key
func getHavenPrivateKey(key cryptotypes.PrivKey) (secretViewKey, secretSpendKey *[32]byte) {
	// generate secret spend key
	h := moneroCrypto.NewHash()
	var keyHash [32]byte
	h.Write(key.Bytes())
	h.Sum(keyHash[:0])
	moneroCrypto.SecretFromSeed(secretSpendKey, &keyHash)
	// genere secret view key
	moneroCrypto.ViewFromSpend(secretViewKey, secretSpendKey)
	return
}

func generateHavenWallet(privViewKey *[32]byte, privSpendKey *[32]byte, walletName string, password string) ([32]byte, [32]byte, string, bool) {
	// generate pubKeys
	var pubSpendKey [32]byte
	moneroCrypto.PublicFromSecret(&pubSpendKey, privSpendKey)
	var pubViewKey [32]byte
	moneroCrypto.PublicFromSecret(&pubViewKey, privViewKey)

	// generate address data
	var addData []byte
	addData = append(addData, pubSpendKey[:]...)
	addData = append(addData, pubViewKey[:]...)

	// generate the walletAddr
	// NOTE: tag is for mainnet
	walletAddr := base58.EncodeAddr(0x05af4, addData)

	if CreateWallet(walletName, walletAddr, hex.EncodeToString(privSpendKey[:]), hex.EncodeToString(privViewKey[:]), password, false) {
		return pubSpendKey, pubViewKey, walletAddr, true
	} else {
		return pubSpendKey, pubSpendKey, walletAddr, false
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
