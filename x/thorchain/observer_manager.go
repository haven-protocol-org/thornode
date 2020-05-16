package thorchain

import (
	"sort"

	"gitlab.com/thorchain/thornode/common"
	cosmos "gitlab.com/thorchain/thornode/common/cosmos"
)

type ObserverManager interface {
	BeginBlock()
	EndBlock(ctx cosmos.Context, keeper Keeper)
	AppendObserver(chain common.Chain, addrs []cosmos.AccAddress)
	List() []cosmos.AccAddress
}

// ObserverManangerImp implement a ObserverManager which will store the
// observers in memory before written to chain
type ObserverMgr struct {
	chains map[common.Chain][]cosmos.AccAddress
}

// NewObserverMgr create a new instance of ObserverManager
func NewObserverMgr() *ObserverMgr {
	return &ObserverMgr{
		chains: make(map[common.Chain][]cosmos.AccAddress, 0),
	}
}

func (om *ObserverMgr) BeginBlock() {
	om.chains = make(map[common.Chain][]cosmos.AccAddress, 0)
}

func (om *ObserverMgr) AppendObserver(chain common.Chain, addrs []cosmos.AccAddress) {
	// combine addresses
	all := append(om.chains[chain], addrs...)

	// ensure uniqueness
	uniq := make([]cosmos.AccAddress, 0, len(all))
	m := make(map[string]bool)
	for _, val := range all {
		if _, ok := m[val.String()]; !ok {
			m[val.String()] = true
			uniq = append(uniq, val)
		}
	}

	om.chains[chain] = uniq
}

// List - gets a list of addresses that have been observed in all chains
func (om *ObserverMgr) List() []cosmos.AccAddress {
	result := make([]cosmos.AccAddress, 0)
	tracker := make(map[string]int, 0)
	for _, addrs := range om.chains {
		for _, addr := range addrs {
			// check if we need to init this key for the tracker
			if _, ok := tracker[addr.String()]; !ok {
				tracker[addr.String()] = 0
			}
			tracker[addr.String()] += 1
		}
	}

	for key, count := range tracker {
		if count >= len(om.chains) {
			addr, _ := cosmos.AccAddressFromBech32(key)
			result = append(result, addr)
		}
	}

	// Sort our list, ensures we avoid a census failure
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].String() < result[j].String()
	})

	return result
}

// EndBlock emit the observers
func (om *ObserverMgr) EndBlock(ctx cosmos.Context, keeper Keeper) {
	if err := keeper.AddObservingAddresses(ctx, om.List()); err != nil {
		ctx.Logger().Error("fail to append observers", "error", err)
	}
}
