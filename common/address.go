package common

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/bech32"
	eth "github.com/ethereum/go-ethereum/common"
	bchchaincfg "github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchutil"
	moneroCryptoBase58 "github.com/haven-protocol-org/monero-go-utils/base58"
	ltcchaincfg "github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcutil"
	"gitlab.com/thorchain/thornode/common/cosmos"
)

type Address string

var NoAddress Address = Address("")

const ETHAddressLen = 42

// NewAddress create a new Address. Supports Binance, Bitcoin, and Ethereum
func NewAddress(address string) (Address, error) {
	if len(address) == 0 {
		return NoAddress, nil
	}

	// Check is eth address
	if eth.IsHexAddress(address) {
		return Address(address), nil
	}

	// Check bech32 addresses, would succeed any string bech32 encoded
	_, _, err := bech32.Decode(address)
	if err == nil {
		return Address(address), nil
	}

	// Check if it is a valid XHV address according to it is prefix/tag.
	prefix := address[:3]
	if prefix == "hvt" || prefix == "hvx" || prefix == "hvs" {
		tag, _ := moneroCryptoBase58.DecodeAddr(address) // gives a out of range exception for other chain adresses so guarded with outer if.
		if tag == 0x59f4 || tag == 0x05af4 {
			return Address(address), nil
		}
	}

	// Check other BTC address formats with mainnet
	_, err = btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err == nil {
		return Address(address), nil
	}

	// Check BTC address formats with testnet
	_, err = btcutil.DecodeAddress(address, &chaincfg.TestNet3Params)
	if err == nil {
		return Address(address), nil
	}

	// Check other LTC address formats with mainnet
	_, err = ltcutil.DecodeAddress(address, &ltcchaincfg.MainNetParams)
	if err == nil {
		return Address(address), nil
	}

	// Check LTC address formats with testnet
	_, err = ltcutil.DecodeAddress(address, &ltcchaincfg.TestNet4Params)
	if err == nil {
		return Address(address), nil
	}

	// Check other BCH address formats with mainnet
	_, err = bchutil.DecodeAddress(address, &bchchaincfg.MainNetParams)
	if err == nil {
		return Address(address), nil
	}

	// Check BCH address formats with testnet
	_, err = bchutil.DecodeAddress(address, &bchchaincfg.TestNet3Params)
	if err == nil {
		return Address(address), nil
	}

	// Check BCH address formats with mocknet
	_, err = bchutil.DecodeAddress(address, &bchchaincfg.RegressionNetParams)
	if err == nil {
		return Address(address), nil
	}

	return NoAddress, fmt.Errorf("address format not supported: %s", address)
}

func (addr Address) IsChain(chain Chain) bool {
	switch chain {
	case ETHChain:
		return strings.HasPrefix(addr.String(), "0x")
	case BNBChain:
		prefix, _, _ := bech32.Decode(addr.String())
		return prefix == "bnb" || prefix == "tbnb"
	case THORChain:
		prefix, _, _ := bech32.Decode(addr.String())
		return prefix == "thor" || prefix == "tthor"
	case BTCChain:
		prefix, _, err := bech32.Decode(addr.String())
		if err == nil && (prefix == "bc" || prefix == "tb") {
			return true
		}
		// Check mainnet other formats
		_, err = btcutil.DecodeAddress(addr.String(), &chaincfg.MainNetParams)
		if err == nil {
			return true
		}
		// Check testnet other formats
		_, err = btcutil.DecodeAddress(addr.String(), &chaincfg.TestNet3Params)
		if err == nil {
			return true
		}
		return false
	case LTCChain:
		prefix, _, err := bech32.Decode(addr.String())
		if err == nil && (prefix == "ltc" || prefix == "tltc" || prefix == "rltc") {
			return true
		}
		// Check mainnet other formats
		_, err = ltcutil.DecodeAddress(addr.String(), &ltcchaincfg.MainNetParams)
		if err == nil {
			return true
		}
		// Check testnet other formats
		_, err = ltcutil.DecodeAddress(addr.String(), &ltcchaincfg.TestNet4Params)
		if err == nil {
			return true
		}
		return false
	case BCHChain:
		// Check mainnet other formats
		_, err := bchutil.DecodeAddress(addr.String(), &bchchaincfg.MainNetParams)
		if err == nil {
			return true
		}
		// Check testnet other formats
		_, err = bchutil.DecodeAddress(addr.String(), &bchchaincfg.TestNet3Params)
		if err == nil {
			return true
		}
		// Check mocknet / regression other formats
		_, err = bchutil.DecodeAddress(addr.String(), &bchchaincfg.RegressionNetParams)
		if err == nil {
			return true
		}
		return false
	default:
		return true // if THORNode don't specifically check a chain yet, assume its ok.
	}
}

func (addr Address) AccAddress() (cosmos.AccAddress, error) {
	return cosmos.AccAddressFromBech32(addr.String())
}

func (addr Address) Equals(addr2 Address) bool {
	return strings.EqualFold(addr.String(), addr2.String())
}

func (addr Address) IsEmpty() bool {
	return strings.TrimSpace(addr.String()) == ""
}

func (addr Address) String() string {
	return string(addr)
}
