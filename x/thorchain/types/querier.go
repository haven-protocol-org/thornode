package types

import (
	"fmt"
	"strings"

	"github.com/blang/semver"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
)

// QueryResLastBlockHeights used to return the block height query
type QueryResLastBlockHeights struct {
	Chain            common.Chain `json:"chain"`
	LastChainHeight  int64        `json:"last_observed_in"`
	LastSignedHeight int64        `json:"last_signed_out"`
	Thorchain        int64        `json:"thorchain"`
}

// String implement fmt.Stringer return a string representation of QueryResLastBlockHeights
func (h QueryResLastBlockHeights) String() string {
	return fmt.Sprintf("Chain: %d, Signed: %d, THORChain: %d", h.LastChainHeight, h.LastSignedHeight, h.Thorchain)
}

// QueryQueue a struct store the total outstanding out items
type QueryQueue struct {
	Swap     int64 `json:"swap"`
	Outbound int64 `json:"outbound"`
}

// String implement fmt.Stringer
func (h QueryQueue) String() string {
	return fmt.Sprintf("Swap: %d, Outboud: %d", h.Swap, h.Outbound)
}

// QueryNodeAccountPreflightCheck is structure to hold all the information need to return to client
// include current node status , and whether it might get churned in next
type QueryNodeAccountPreflightCheck struct {
	Status      NodeStatus `json:"status"`
	Description string     `json:"reason"`
	Code        int        `json:"code"`
}

// String implement fmt.Stringer
func (n QueryNodeAccountPreflightCheck) String() string {
	sb := strings.Builder{}
	sb.WriteString("Result Status:" + n.Status.String() + "\n")
	sb.WriteString("Description:" + n.Description + "\n")
	return sb.String()
}

// QueryKeygenBlock query keygen, displays signed keygen requests
type QueryKeygenBlock struct {
	KeygenBlock KeygenBlock `json:"keygen_block"`
	Signature   string      `json:"signature"`
}

// String implement fmt.Stringer
func (n QueryKeygenBlock) String() string {
	return n.KeygenBlock.String()
}

// QueryKeysign query keysign result
type QueryKeysign struct {
	Keysign   TxOut  `json:"keysign"`
	Signature string `json:"signature"`
}

// QueryYggdrasilVaults query yggdrasil vault result
type QueryYggdrasilVaults struct {
	Vault      Vault               `json:"vault"`
	Status     NodeStatus          `json:"status"`
	Bond       cosmos.Uint         `json:"bond"`
	TotalValue cosmos.Uint         `json:"total_value"`
	Addresses  []QueryChainAddress `json:"addresses"`
}

type QueryVersion struct {
	Current semver.Version `json:"current"`
	Next    semver.Version `json:"next"`
}

type QueryChainAddress struct {
	Chain   common.Chain   `json:"chain"`
	Address common.Address `json:"address"`
}

// QueryChainHeight chain height
type QueryChainHeight struct {
	Chain  common.Chain `json:"chain"`
	Height int64        `json:"height"`
}

// QueryNodeAccount hold all the information related to node account
type QueryNodeAccount struct {
	NodeAddress         cosmos.AccAddress              `json:"node_address"`
	Status              NodeStatus                     `json:"status"`
	PubKeySet           common.PubKeySet               `json:"pub_key_set"`
	ValidatorConsPubKey string                         `json:"validator_cons_pub_key"`
	Bond                cosmos.Uint                    `json:"bond"`
	ActiveBlockHeight   int64                          `json:"active_block_height"`
	BondAddress         common.Address                 `json:"bond_address"`
	StatusSince         int64                          `json:"status_since"`
	SignerMembership    common.PubKeys                 `json:"signer_membership"`
	RequestedToLeave    bool                           `json:"requested_to_leave"`
	ForcedToLeave       bool                           `json:"forced_to_leave"`
	LeaveScore          uint64                         `json:"leave_height"`
	IPAddress           string                         `json:"ip_address"`
	Version             semver.Version                 `json:"version"`
	SlashPoints         int64                          `json:"slash_points"`
	Jail                Jail                           `json:"jail"`
	CurrentAward        cosmos.Uint                    `json:"current_award"`
	ObserveChains       []QueryChainHeight             `json:"observe_chains"`
	PreflightStatus     QueryNodeAccountPreflightCheck `json:"preflight_status"`
}

// NewQueryNodeAccount create a new QueryNodeAccount based on the given node account parameter
func NewQueryNodeAccount(na NodeAccount) QueryNodeAccount {
	return QueryNodeAccount{
		NodeAddress:         na.NodeAddress,
		Status:              na.Status,
		PubKeySet:           na.PubKeySet,
		ValidatorConsPubKey: na.ValidatorConsPubKey,
		Bond:                na.Bond,
		ActiveBlockHeight:   na.ActiveBlockHeight,
		BondAddress:         na.BondAddress,
		StatusSince:         na.StatusSince,
		SignerMembership:    na.GetSignerMembership(),
		RequestedToLeave:    na.RequestedToLeave,
		ForcedToLeave:       na.ForcedToLeave,
		LeaveScore:          na.LeaveScore,
		IPAddress:           na.IPAddress,
		Version:             na.GetVersion(),
	}
}

// QueryVaultPubKeyContract is a type to combine PubKey and it's related contract
type QueryVaultPubKeyContract struct {
	PubKey         common.PubKey   `json:"pub_key"`
	Routers        []ChainContract `json:"routers"`
	CryptonoteData string          `json:"cryptonote_data"`
}

// QueryVaultsPubKeys represent the result for query vaults pubkeys
type QueryVaultsPubKeys struct {
	Asgard    []QueryVaultPubKeyContract `json:"asgard"`
	Yggdrasil []QueryVaultPubKeyContract `json:"yggdrasil"`
}
