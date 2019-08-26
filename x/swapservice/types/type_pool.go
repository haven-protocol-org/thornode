package types

import (
	"encoding/json"
	"fmt"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/pkg/errors"
	common "gitlab.com/thorchain/bepswap/common"
)

// PoolStatus is an indication of what the pool state is
type PoolStatus int

//| State | ADMIN-MEMO | Swapping | Staking | Withdrawing | Refunding |
//| ------ | ------ | ------ | ------ | ------ | ------ |
//| `bootstrap` |  `ADMIN:POOL:BOOTSTRAP` | no | yes | yes | Refund Invalid Stakes && all Swaps |
//| `enabled` |  `ADMIN:POOL:ENABLE` | yes | yes | yes | Refund Invalid Tx |
//| `suspended` | `ADMIN:POOL:SUSPEND` | no | no | no | Refund all |
const (
	Enabled PoolStatus = iota
	Bootstrap
	Suspended
)

var poolStatusStr = map[string]PoolStatus{
	"Enabled":   Enabled,
	"Bootstrap": Bootstrap,
	"Suspended": Suspended,
}

// String implement stringer
func (ps PoolStatus) String() string {
	for key, item := range poolStatusStr {
		if item == ps {
			return key
		}
	}
	return ""
}

func (ps PoolStatus) Valid() error {
	if ps.String() == "" {
		return fmt.Errorf("Invalid pool status")
	}
	return nil
}

// MarshalJSON marshal PoolStatus to JSON in string form
func (ps PoolStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(ps.String())
}

// UnmarshalJSON convert string form back to PoolStatus
func (ps *PoolStatus) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); nil != err {
		return err
	}
	*ps = GetPoolStatus(s)
	return nil
}

// GetPoolStatus from string
func GetPoolStatus(ps string) PoolStatus {
	for key, item := range poolStatusStr {
		if strings.EqualFold(key, ps) {
			return item
		}
	}

	return Suspended
}

// Pool is a struct that contains all the metadata of a pooldata
// This is the structure we will saved to the key value store
type Pool struct {
	BalanceRune  common.Amount     `json:"balance_rune"`  // how many RUNE in the pool
	BalanceToken common.Amount     `json:"balance_token"` // how many token in the pool
	Ticker       common.Ticker     `json:"ticker"`        // what's the token's ticker
	PoolUnits    common.Amount     `json:"pool_units"`    // total units of the pool
	PoolAddress  common.BnbAddress `json:"pool_address"`  // bnb liquidity pool address
	Status       PoolStatus        `json:"status"`        // status
}

// NewPool Returns a new Pool
func NewPool() Pool {
	return Pool{
		BalanceRune:  common.ZeroAmount,
		BalanceToken: common.ZeroAmount,
		PoolUnits:    common.ZeroAmount,
		Status:       Bootstrap,
	}
}

func (ps Pool) Empty() bool {
	return ps.Ticker == ""
}

// String implement fmt.Stringer
func (ps Pool) String() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintln("rune-balance: " + ps.BalanceRune.String()))
	sb.WriteString(fmt.Sprintln("token-balance: " + ps.BalanceToken.String()))
	sb.WriteString(fmt.Sprintln("ticker: " + ps.Ticker.String()))
	sb.WriteString(fmt.Sprintln("pool-units: " + ps.PoolUnits.String()))
	sb.WriteString(fmt.Sprintln("status: " + ps.Status.String()))
	return sb.String()
}

// EnsureValidPoolStatus
func (ps Pool) EnsureValidPoolStatus(msg sdk.Msg) error {
	switch ps.Status {
	case Enabled:
		return nil
	case Bootstrap:
		switch msg.(type) {
		case MsgSwap:
			return errors.New("pool is in bootstrap status, can't swap")
		default:
			return nil
		}
	case Suspended:
		return errors.New("pool suspended")
	default:
		return errors.Errorf("unknown pool status,%s", ps.Status)
	}
}

// TokenPrice is how much 1 token worth in RUNE
func (ps Pool) TokenPriceInRune() float64 {
	if ps.BalanceRune.IsZero() || ps.BalanceRune.IsEmpty() || ps.BalanceToken.IsZero() || ps.BalanceToken.IsEmpty() {
		return common.ZeroAmount.Float64()
	}
	return ps.BalanceRune.Float64() / ps.BalanceToken.Float64()
}