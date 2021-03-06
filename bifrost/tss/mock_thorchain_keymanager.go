package tss

import (
	"encoding/base64"

	"github.com/tendermint/tendermint/crypto"
	ctypes "gitlab.com/thorchain/binance-sdk/common/types"
	"gitlab.com/thorchain/binance-sdk/keys"
	"gitlab.com/thorchain/binance-sdk/types/tx"

	"gitlab.com/thorchain/thornode/common"
)

// MockThorchainKeymanager is to mock the TSS , so as we could test it
type MockThorchainKeyManager struct{}

func (k *MockThorchainKeyManager) Sign(tx.StdSignMsg) ([]byte, error) {
	return nil, nil
}

func (k *MockThorchainKeyManager) GetPrivKey() crypto.PrivKey {
	return nil
}

func (k *MockThorchainKeyManager) GetAddr() ctypes.AccAddress {
	return nil
}

func (k *MockThorchainKeyManager) ExportAsMnemonic() (string, error) {
	return "", nil
}

func (k *MockThorchainKeyManager) ExportAsPrivateKey() (string, error) {
	return "", nil
}

func (k *MockThorchainKeyManager) ExportAsKeyStore(password string) (*keys.EncryptedKeyJSON, error) {
	return nil, nil
}

func (k *MockThorchainKeyManager) SignWithPool(msg tx.StdSignMsg, poolPubKey common.PubKey) ([]byte, error) {
	return nil, nil
}

func (k *MockThorchainKeyManager) RemoteSign(msg []byte, poolPubKey string) ([]byte, []byte, error) {
	// this is the key we are using to test TSS keysign result in BTC chain
	// tthorpub1addwnpepqwznsrgk2t5vn2cszr6ku6zned6tqxknugzw3vhdcjza284d7djp5rql6vn
	if poolPubKey == "tthorpub1addwnpepqwznsrgk2t5vn2cszr6ku6zned6tqxknugzw3vhdcjza284d7djp5rql6vn" {
		msgToSign := base64.StdEncoding.EncodeToString(msg)
		if msgToSign == "wqYuqkdeLjxtkKjmeAK0fOZygdw8zZgsDaJX7mrqWRE=" {
			sig, err := getSignature("ku/n0D18euwqkgM0kZn0OVX9+D7wfDBIWBMya1SGxWg=", "fw0sE6osjVN6vQtr9WxFrOpdxizPz9etSTOKGdjDY9A=")
			return sig, nil, err
		} else {
			sig, err := getSignature("256CpfiML7BDP1nXqKRc3Fq01PALeKwpXYv9P/H3Xhk=", "LoX6cVND0JN8bbZSTsoJcwLCysAKhyYtB2BFM3sdP98=")
			return sig, nil, err
		}
	}
	if poolPubKey == "tthorpub1addwnpepqw2k68efthm08f0f5akhjs6fk5j2pze4wkwt4fmnymf9yd463puruhh0lyz" {
		msgToSign := base64.StdEncoding.EncodeToString(msg)
		if msgToSign == "BMxXf+K+1dYu3qGgvH59GXoxwwFfTnLjB7hHf3qflPk=" {
			sig, err := getSignature("WGSFUPPCN0kTcXcylAIQXyAxO7OUC5YRjDRz9wmzpkk=", "RUIoqdza5Od9nMfU2teqbZJAeC+pTyHIbKq+72jJMfM=")
			return sig, nil, err
		} else {
			sig, err := getSignature("gVxKdVgWR+4OZLxFAu5uWWOPCxhGPqFtQAyVujqSuh8=", "JXPU4Li4spnonssxJS52r/hEBwt1iPFlvjwu8ZOe+F0=")
			return sig, nil, err
		}
	}
	return nil, nil, nil
}

func (k *MockThorchainKeyManager) RemoteSignMn(msg []byte, poolPubKey string) (string, string, error) {
	return "", "", nil
}
