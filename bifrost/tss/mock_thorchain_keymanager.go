package tss

import (
	ctypes "github.com/binance-chain/go-sdk/common/types"
	"github.com/binance-chain/go-sdk/keys"
	"github.com/binance-chain/go-sdk/types/tx"
	"github.com/tendermint/tendermint/crypto"

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
	// tthorpub1addwnpepqwm9wsafv26hzqurtjvuuj3xk4j3jyc9yj2uastnmuuqjney9ep3clzt622
	if poolPubKey == "tthorpub1addwnpepqwm9wsafv26hzqurtjvuuj3xk4j3jyc9yj2uastnmuuqjney9ep3clzt622" {
		sig, err := getSignature("VqAlcVM+9ciiCL+/VBVNjekbLUjB5/NXI6ui0ZdTRZM=", "ENP93vjudq9s+UQu87nFPDZ1LKNurzRTo/hMIqetAb4=")
		return sig, nil, err
	}
	// this is the key we are using to test TSS keysign result in BCH chain
	// tthorpub1addwnpepqw2k68efthm08f0f5akhjs6fk5j2pze4wkwt4fmnymf9yd463puruhh0lyz
	if poolPubKey == "tthorpub1addwnpepqw2k68efthm08f0f5akhjs6fk5j2pze4wkwt4fmnymf9yd463puruhh0lyz" {
		sig, err := getSignature("1C7Tn7XHX9JAPGoOQKK14CpTGd7W8fyq0iWP5DNt2DY=", "GjDYG1zmAo7JHdtiP7l+s4PRFiV7cH9d4bDoeEMrQgo=")
		return sig, nil, err
	}
	return nil, nil, nil
}
