package haven

import (
	"encoding/hex"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
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

func generateHavenWallet(privSpendKey *[32]byte, privViewKey *[32]byte, walletName string, password string) ([32]byte, [32]byte, common.Address, error) {
	// generate pubKeys
	var pubSpendKey [32]byte
	moneroCrypto.PublicFromSecret(&pubSpendKey, privSpendKey)
	var pubViewKey [32]byte
	moneroCrypto.PublicFromSecret(&pubViewKey, privViewKey)

	// generate cryptonote data and get wallet address
	var cnData []byte
	cnData = append(cnData, privViewKey[:]...)
	cnData = append(cnData, pubSpendKey[:]...)
	walletAddr, err := common.PubKey(hex.EncodeToString(cnData)).GetAddress(common.XHVChain)
	if err != nil {
		return pubSpendKey, pubSpendKey, "", err
	}

	// create the wallet
	err = CreateWallet(walletName, walletAddr.String(), hex.EncodeToString(privSpendKey[:]), hex.EncodeToString(privViewKey[:]), password, false)
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
func (w *KeySignWrapper) Sign(poolPubKey common.PubKey) TssSignable {
	// s, err := NewTssSignable(poolPubKey, w.tssKeyManager, w.keySignPartyMgr)
	// if err != nil {
	// 	w.logger.Err(err).Msg("fail to create tss signable")
	// 	return nil
	// }
	return TssSignable{}
}
