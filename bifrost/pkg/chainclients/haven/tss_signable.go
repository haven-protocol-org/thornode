package haven

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"gitlab.com/thorchain/thornode/bifrost/tss"
	"gitlab.com/thorchain/thornode/common"
)

// TssSignable is a signable implementation backed by tss
type TssSignable struct {
	poolPubKey    common.PubKey
	tssKeyManager tss.ThorchainKeyManager
	logger        zerolog.Logger
}

// NewTssSignable create a new instance of TssSignable
func NewTssSignable(pubKey common.PubKey, manager tss.ThorchainKeyManager) (*TssSignable, error) {
	return &TssSignable{
		poolPubKey:    pubKey,
		tssKeyManager: manager,
		logger:        log.Logger.With().Str("module", "tss_signable").Logger(),
	}, nil
}

// func (ts *TssSignable) GetPubKey() *btcec.PublicKey {
// 	cpk, err := cosmos.GetPubKeyFromBech32(cosmos.Bech32PubKeyTypeAccPub, ts.poolPubKey.String())
// 	if err != nil {
// 		ts.logger.Err(err).Str("pubkey", ts.poolPubKey.String()).Msg("fail to get pubic key from the bech32 pool public key string")
// 		return nil
// 	}
// 	secpPubKey, ok := cpk.(secp256k1.PubKeySecp256k1)
// 	if !ok {
// 		ts.logger.Error().Str("pubkey", ts.poolPubKey.String()).Msg("it is not a secp256 k1 public key")
// 		return nil
// 	}
// 	newPubkey, err := btcec.ParsePubKey(secpPubKey[:], btcec.S256())
// 	if err != nil {
// 		ts.logger.Err(err).Msg("fail to parse public key")
// 		return nil
// 	}
// 	return newPubkey
// }
