package types

import (
	"errors"
	"fmt"
	"sort"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
)

// Vaults a list of vault
type Vaults []Vault

// NewVault create a new instance of vault
func NewVault(height int64, status VaultStatus, vtype VaultType, pk common.PubKey, chains []string, contracts []ChainContract) Vault {
	return Vault{
		BlockHeight: height,
		StatusSince: height,
		PubKey:      pk,
		Coins:       make(common.Coins, 0),
		Type:        vtype,
		Status:      status,
		Chains:      chains,
		Contracts:   contracts,
	}
}

func (m Vault) GetChains() common.Chains {
	chains := make(common.Chains, 0)
	for _, c := range m.Chains {
		chain, err := common.NewChain(c)
		if err != nil {
			continue
		}
		chains = append(chains, chain)
	}
	return chains
}

func (m Vault) GetMembership() common.PubKeys {
	pubkeys := make(common.PubKeys, 0)
	for _, pk := range m.Membership {
		pk, err := common.NewPubKey(pk)
		if err != nil {
			continue
		}
		pubkeys = append(pubkeys, pk)
	}
	return pubkeys
}

// IsType determine whether the vault is given type
func (m Vault) IsType(vtype VaultType) bool {
	return m.Type == vtype
}

// IsAsgard check whether the vault is Asgard vault, it returns true when it is an asgard vault
func (m Vault) IsAsgard() bool {
	return m.IsType(VaultType_AsgardVault)
}

// IsYggdrasil return true when the vault is YggdrasilVault
func (m Vault) IsYggdrasil() bool {
	return m.IsType(VaultType_YggdrasilVault)
}

// IsEmpty returns true when the vault pubkey is empty
func (m Vault) IsEmpty() bool {
	return m.PubKey.IsEmpty()
}

// Contains check whether the given pubkey is party of the originally node who create this vault
func (m Vault) Contains(pubkey common.PubKey) bool {
	return m.GetMembership().Contains(pubkey)
}

// MembershipEquals check whether the vault has the same membership as the given pubkeys
func (m Vault) MembershipEquals(pks common.PubKeys) bool {
	if len(m.Membership) != len(pks) {
		return false
	}
	for _, pk := range pks {
		if !m.Contains(pk) {
			return false
		}
	}
	return true
}

// UpdateStatus set the vault to given status
func (m *Vault) UpdateStatus(s VaultStatus, height int64) {
	m.Status = s
	m.StatusSince = height
}

// Valid check whether Vault has all necessary values
func (m Vault) Valid() error {
	if m.PubKey.IsEmpty() {
		return errors.New("pubkey cannot be empty")
	}
	return nil
}

// HasFunds check whether the vault pool has fund
func (m Vault) HasFunds() bool {
	for _, coin := range m.Coins {
		if !coin.Asset.IsRune() { // non-native rune is omitted from the calculation
			if !coin.Amount.IsZero() {
				return true
			}
		}
	}
	return false
}

// HasFundsForChain check whether the vault pool has funds for a specific chain
func (m Vault) HasFundsForChain(chain common.Chain) bool {
	for _, coin := range m.Coins {
		if coin.Asset.Chain.Equals(chain) && !coin.Amount.IsZero() {
			return true
		}
	}
	return false
}

// CoinLength - counts the number of coins this vault has
func (m Vault) CoinLength() (count int) {
	for _, coin := range m.Coins {
		if !coin.Amount.IsZero() {
			count++
		}
	}
	return
}

// CoinLengthByChain - count the number of coins this vault has for the given chain
func (m Vault) CoinLengthByChain(c common.Chain) int {
	total := 0
	for _, coin := range m.Coins {
		if coin.Asset.IsRune() {
			continue
		}
		if coin.Asset.Chain.Equals(c) && !coin.Amount.IsZero() {
			total++
		}
	}
	return total
}

// HasAsset Check if this vault has a particular asset
func (m Vault) HasAsset(asset common.Asset) bool {
	return !m.GetCoin(asset).Amount.IsZero()
}

// GetCoin return coin type of given asset
func (m Vault) GetCoin(asset common.Asset) common.Coin {
	for _, coin := range m.Coins {
		if coin.Asset.Equals(asset) {
			return coin
		}
	}
	return common.NewCoin(asset, cosmos.ZeroUint())
}

// GetMembers return members who's address exist in the given list
func (m Vault) GetMembers(activeObservers []cosmos.AccAddress) (common.PubKeys, error) {
	signers := common.PubKeys{}
	for _, k := range m.GetMembership() {
		addr, err := k.GetThorAddress()
		if err != nil {
			return common.PubKeys{}, fmt.Errorf("fail to get thor address: %w", err)
		}
		for _, item := range activeObservers {
			if item.Equals(addr) {
				signers = append(signers, k)
			}
		}
	}
	return signers, nil
}

// GetContract return the contract that match the request chain
func (v Vault) GetContract(chain common.Chain) ChainContract {
	for _, item := range v.Contracts {
		if item.Chain.Equals(chain) {
			return item
		}
	}
	return ChainContract{}
}

// UpdateContract update the chain contract
func (v *Vault) UpdateContract(chainContract ChainContract) {
	exist := false
	for i, item := range v.Contracts {
		if item.Chain.Equals(chainContract.Chain) {
			v.Contracts[i] = chainContract
			exist = true
		}
	}
	if !exist {
		v.Contracts = append(v.Contracts, chainContract)
	}
}

// AddFunds add given coins into vault
func (m *Vault) AddFunds(coins common.Coins) {
	for _, coin := range coins {
		m.addFund(coin)
	}
}

func (m *Vault) addFund(coin common.Coin) {
	for i, ycoin := range m.Coins {
		if ycoin.Asset.Equals(coin.Asset) {
			m.Coins[i].Amount = ycoin.Amount.Add(coin.Amount)
			return
		}
	}

	if !m.GetChains().Has(coin.Asset.Chain) {
		m.Chains = append(m.Chains, coin.Asset.Chain.String())
	}

	m.Coins = append(m.Coins, coin)
}

// SubFunds subtract given coins from vault
func (m *Vault) SubFunds(coins common.Coins) {
	for _, coin := range coins {
		m.subFund(coin)
	}
}

func (m *Vault) subFund(coin common.Coin) {
	for i, ycoin := range m.Coins {
		if coin.Asset.Equals(ycoin.Asset) {
			m.Coins[i].Amount = common.SafeSub(ycoin.Amount, coin.Amount)
			return
		}
	}
}

// AppendPendingTxBlockHeights will add current block height into the list , also remove the block height that is too old
func (m *Vault) AppendPendingTxBlockHeights(blockHeight int64, constAccessor constants.ConstantValues) {
	heights := []int64{blockHeight}
	for _, item := range m.PendingTxBlockHeights {
		if (blockHeight - item) <= constAccessor.GetInt64Value(constants.SigningTransactionPeriod) {
			heights = append(heights, item)
		}
	}
	m.PendingTxBlockHeights = heights
}

// RemovePendingTxBlockHeights remove the given block height from internal pending tx block height
func (m *Vault) RemovePendingTxBlockHeights(blockHeight int64) {
	idxToRemove := -1
	for idx, item := range m.PendingTxBlockHeights {
		if item == blockHeight {
			idxToRemove = idx
			break
		}
	}
	if idxToRemove != -1 {
		m.PendingTxBlockHeights = append(m.PendingTxBlockHeights[:idxToRemove], m.PendingTxBlockHeights[idxToRemove+1:]...)
	}
}

// LenPendingTxBlockHeights count how many outstanding block heights in the vault
// if the a block height is older than SigningTransactionPeriod , it will ignore
func (m *Vault) LenPendingTxBlockHeights(currentBlockHeight int64, constAccessor constants.ConstantValues) int {
	total := 0
	for _, item := range m.PendingTxBlockHeights {
		if (currentBlockHeight - item) <= constAccessor.GetInt64Value(constants.SigningTransactionPeriod) {
			total++
		}
	}
	return total
}

// SortBy order coins by the given asset
func (vs Vaults) SortBy(sortBy common.Asset) Vaults {
	// use the vault pool with the highest quantity of our coin
	sort.SliceStable(vs[:], func(i, j int) bool {
		return vs[i].GetCoin(sortBy).Amount.GT(vs[j].GetCoin(sortBy).Amount)
	})
	return vs
}

// SelectByMinCoin return the vault that has least of given asset
func (vs Vaults) SelectByMinCoin(asset common.Asset) (vault Vault) {
	if len(vs) == 1 {
		vault = vs[0]
		return
	}
	for _, v := range vs {
		if vault.IsEmpty() || v.GetCoin(asset).Amount.LT(vault.GetCoin(asset).Amount) {
			vault = v
		}
	}
	return
}

// SelectByMaxCoin return the vault that has most of given asset
func (vs Vaults) SelectByMaxCoin(asset common.Asset) (vault Vault) {
	if len(vs) == 1 {
		vault = vs[0]
		return
	}
	for _, v := range vs {
		if vault.IsEmpty() || v.GetCoin(asset).Amount.GT(vault.GetCoin(asset).Amount) {
			vault = v
		}
	}
	return
}

// HasAddress will go through the vaults to determinate whether any of the
// vault match the given address on the given chain
func (vs Vaults) HasAddress(chain common.Chain, address common.Address) (bool, error) {
	for _, item := range vs {
		addr, err := item.PubKey.GetAddress(chain)
		if err != nil {
			return false, fmt.Errorf("fail to get address from (%s) for chain(%s)", item.PubKey, chain)
		}
		if addr.Equals(address) {
			return true, nil
		}
	}
	return false, nil
}
