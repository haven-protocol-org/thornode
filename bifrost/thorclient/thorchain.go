package thorclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blang/semver"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	rpchttp "github.com/tendermint/tendermint/rpc/client/http"

	"gitlab.com/thorchain/thornode/app"
	"gitlab.com/thorchain/thornode/bifrost/config"
	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	stypes "gitlab.com/thorchain/thornode/x/thorchain/types"
)

// Endpoint urls
const (
	AuthAccountEndpoint      = "/auth/accounts"
	BroadcastTxsEndpoint     = "/"
	KeygenEndpoint           = "/thorchain/keygen"
	KeysignEndpoint          = "/thorchain/keysign"
	LastBlockEndpoint        = "/thorchain/lastblock"
	NodeAccountEndpoint      = "/thorchain/node"
	SignerMembershipEndpoint = "/thorchain/vaults/%s/signers"
	StatusEndpoint           = "/status"
	AsgardVault              = "/thorchain/vaults/asgard"
	PubKeysEndpoint          = "/thorchain/vaults/pubkeys"
	ThorchainConstants       = "/thorchain/constants"
	RagnarokEndpoint         = "/thorchain/ragnarok"
	MimirEndpoint            = "/thorchain/mimir"
	ChainVersionEndpoint     = "/thorchain/version"
	InboundAddressesEndpoint = "/thorchain/inbound_addresses"
	PoolsEndpoint            = "/thorchain/pools"
)

// ThorchainBridge will be used to send tx to THORChain
type ThorchainBridge struct {
	logger        zerolog.Logger
	cfg           config.ClientConfiguration
	keys          *Keys
	errCounter    *prometheus.CounterVec
	m             *metrics.Metrics
	blockHeight   int64
	accountNumber uint64
	seqNumber     uint64
	httpClient    *retryablehttp.Client
	broadcastLock *sync.RWMutex
}

// NewThorchainBridge create a new instance of ThorchainBridge
func NewThorchainBridge(cfg config.ClientConfiguration, m *metrics.Metrics, k *Keys) (*ThorchainBridge, error) {
	// main module logger
	logger := log.With().Str("module", "thorchain_client").Logger()

	if len(cfg.ChainID) == 0 {
		return nil, errors.New("chain id is empty")
	}
	if len(cfg.ChainHost) == 0 {
		return nil, errors.New("chain host is empty")
	}

	httpClient := retryablehttp.NewClient()
	httpClient.Logger = nil

	return &ThorchainBridge{
		logger:        logger,
		cfg:           cfg,
		keys:          k,
		errCounter:    m.GetCounterVec(metrics.ThorchainClientError),
		httpClient:    httpClient,
		m:             m,
		broadcastLock: &sync.RWMutex{},
	}, nil
}

func MakeCodec() codec.ProtoCodecMarshaler {
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(interfaceRegistry)
	stypes.RegisterInterfaces(interfaceRegistry)
	return codec.NewProtoCodec(interfaceRegistry)
}

// MakeLegacyCodec creates codec
func MakeLegacyCodec() *codec.LegacyAmino {
	cdc := codec.NewLegacyAmino()
	banktypes.RegisterLegacyAminoCodec(cdc)
	authtypes.RegisterLegacyAminoCodec(cdc)
	cosmos.RegisterCodec(cdc)
	stypes.RegisterCodec(cdc)
	return cdc
}

// GetContext return a valid context with all relevant values set
func (b *ThorchainBridge) GetContext() client.Context {
	ctx := client.Context{}
	ctx = ctx.WithKeyring(b.keys.GetKeybase())
	ctx = ctx.WithChainID("thorchain")
	ctx = ctx.WithHomeDir(b.cfg.ChainHomeFolder)
	ctx = ctx.WithFromName(b.cfg.SignerName)
	ctx = ctx.WithFromAddress(b.keys.GetSignerInfo().GetAddress())
	ctx = ctx.WithBroadcastMode("sync")

	encodingConfig := app.MakeEncodingConfig()
	ctx = ctx.WithJSONMarshaler(encodingConfig.Marshaler)
	ctx = ctx.WithInterfaceRegistry(encodingConfig.InterfaceRegistry)
	ctx = ctx.WithTxConfig(encodingConfig.TxConfig)
	ctx = ctx.WithLegacyAmino(encodingConfig.Amino)
	ctx = ctx.WithAccountRetriever(authtypes.AccountRetriever{})

	remote := b.cfg.ChainRPC
	if !strings.HasSuffix(b.cfg.ChainHost, "http") {
		remote = fmt.Sprintf("tcp://%s", remote)
	}
	ctx = ctx.WithNodeURI(remote)
	client, err := rpchttp.New(remote, "/websocket")
	if err != nil {
		panic(err)
	}
	ctx = ctx.WithClient(client)
	return ctx
}

func (b *ThorchainBridge) getWithPath(path string) ([]byte, int, error) {
	return b.get(b.getThorChainURL(path))
}

// get handle all the low level http GET calls using retryablehttp.ThorchainBridge
func (b *ThorchainBridge) get(url string) ([]byte, int, error) {
	resp, err := b.httpClient.Get(url)
	if err != nil {
		b.errCounter.WithLabelValues("fail_get_from_thorchain", "").Inc()
		return nil, http.StatusNotFound, fmt.Errorf("failed to GET from thorchain: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			b.logger.Error().Err(err).Msg("failed to close response body")
		}
	}()

	buf, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return buf, resp.StatusCode, errors.New("Status code: " + resp.Status + " returned")
	}
	if err != nil {
		b.errCounter.WithLabelValues("fail_read_thorchain_resp", "").Inc()
		return nil, resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}
	return buf, resp.StatusCode, nil
}

// post handle all the low level http POST calls using retryablehttp.ThorchainBridge
func (b *ThorchainBridge) post(path, bodyType string, body interface{}) ([]byte, error) {
	resp, err := b.httpClient.Post(b.getThorChainURL(path), bodyType, body)
	if err != nil {
		b.errCounter.WithLabelValues("fail_post_to_thorchain", "").Inc()
		return nil, fmt.Errorf("failed to POST to thorchain: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			b.logger.Error().Err(err).Msg("failed to close response body")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Status code: " + strconv.Itoa(resp.StatusCode) + " returned")
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		b.errCounter.WithLabelValues("fail_read_thorchain_resp", "").Inc()
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return buf, nil
}

// getThorChainURL with the given path
func (b *ThorchainBridge) getThorChainURL(path string) string {
	uri := url.URL{
		Scheme: "http",
		Host:   b.cfg.ChainHost,
		Path:   path,
	}
	return uri.String()
}

// getAccountNumberAndSequenceNumber returns account and Sequence number required to post into thorchain
func (b *ThorchainBridge) getAccountNumberAndSequenceNumber() (uint64, uint64, error) {
	path := fmt.Sprintf("%s/%s", AuthAccountEndpoint, b.keys.GetSignerInfo().GetAddress())

	body, _, err := b.getWithPath(path)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get auth accounts: %w", err)
	}

	var resp types.AccountResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, 0, fmt.Errorf("failed to unmarshal account resp: %w", err)
	}
	acc := resp.Result.Value

	return acc.AccountNumber, acc.Sequence, nil
}

// GetConfig return the configuration
func (b *ThorchainBridge) GetConfig() config.ClientConfiguration {
	return b.cfg
}

// PostKeysignFailure generate and  post a keysign fail tx to thorchan
func (b *ThorchainBridge) PostKeysignFailure(blame stypes.Blame, height int64, memo string, coins common.Coins, pubkey common.PubKey) (common.TxID, error) {
	start := time.Now()
	defer func() {
		b.m.GetHistograms(metrics.SignToThorchainDuration).Observe(time.Since(start).Seconds())
	}()
	msg := stypes.NewMsgTssKeysignFail(height, blame, memo, coins, b.keys.GetSignerInfo().GetAddress(), pubkey)
	return b.Broadcast(msg)
}

// GetErrataStdTx get errata tx from params
func (b *ThorchainBridge) GetErrataMsg(txID common.TxID, chain common.Chain) sdk.Msg {
	return stypes.NewMsgErrataTx(txID, chain, b.keys.GetSignerInfo().GetAddress())
}

// GetKeygenStdTx get keygen tx from params
func (b *ThorchainBridge) GetKeygenStdTx(poolPubKey common.PubKey, cnData string, blame stypes.Blame, inputPks common.PubKeys, keygenType stypes.KeygenType, chains common.Chains, height, keygenTime int64) sdk.Msg {
	return stypes.NewMsgTssPool(inputPks.Strings(), poolPubKey, cnData, keygenType, height, blame, chains.Strings(), b.keys.GetSignerInfo().GetAddress(), keygenTime)
}

// GetObservationsStdTx get observations tx from txIns
func (b *ThorchainBridge) GetObservationsStdTx(txIns stypes.ObservedTxs) ([]cosmos.Msg, error) {
	if len(txIns) == 0 {
		return nil, errors.New("nothing to be signed")
	}
	var inbound stypes.ObservedTxs
	var outbound stypes.ObservedTxs

	// spilt our txs into inbound vs outbound txs
	for _, tx := range txIns {
		chain := common.BNBChain
		if len(tx.Tx.Coins) > 0 {
			chain = tx.Tx.Coins[0].Asset.Chain
		}

		obAddr, err := tx.ObservedPubKey.GetAddress(chain)
		if err != nil {
			return nil, err
		}
		if tx.Tx.ToAddress.Equals(obAddr) {
			inbound = append(inbound, tx)
		} else if tx.Tx.FromAddress.Equals(obAddr) {
			outbound = append(outbound, tx)
		} else {
			return nil, errors.New("could not determine if this tx as inbound or outbound")
		}
	}

	var msgs []cosmos.Msg
	if len(inbound) > 0 {
		msgs = append(msgs, stypes.NewMsgObservedTxIn(inbound, b.keys.GetSignerInfo().GetAddress()))
	}
	if len(outbound) > 0 {
		msgs = append(msgs, stypes.NewMsgObservedTxOut(outbound, b.keys.GetSignerInfo().GetAddress()))
	}

	return msgs, nil
}

// EnsureNodeWhitelistedWithTimeout check node is whitelisted with timeout retry
func (b *ThorchainBridge) EnsureNodeWhitelistedWithTimeout() error {
	for {
		select {
		case <-time.After(time.Hour):
			return errors.New("Observer is not whitelisted yet")
		default:
			err := b.EnsureNodeWhitelisted()
			if err == nil {
				// node had been whitelisted
				return nil
			}
			b.logger.Error().Err(err).Msg("observer is not whitelisted , will retry a bit later")
			time.Sleep(time.Second * 30)
		}
	}
}

// EnsureNodeWhitelisted will call to thorchain to check whether the observer had been whitelist or not
func (b *ThorchainBridge) EnsureNodeWhitelisted() error {
	status, err := b.FetchNodeStatus()
	if err != nil {
		return fmt.Errorf("failed to get node status: %w", err)
	}
	if status == stypes.NodeStatus_Disabled || status == stypes.NodeStatus_Unknown {
		return fmt.Errorf("node account status %s , will not be able to forward transaction to thorchain", status)
	}
	return nil
}

// FetchNodeStatus get current node status from thorchain
func (b *ThorchainBridge) FetchNodeStatus() (stypes.NodeStatus, error) {
	bepAddr := b.keys.GetSignerInfo().GetAddress().String()
	if len(bepAddr) == 0 {
		return stypes.NodeStatus_Unknown, errors.New("bep address is empty")
	}
	na, err := b.GetNodeAccount(bepAddr)
	if err != nil {
		return stypes.NodeStatus_Unknown, fmt.Errorf("failed to get node status: %w", err)
	}
	return na.Status, nil
}

// GetKeysignParty call into thorchain to get the node accounts that should be join together to sign the message
func (b *ThorchainBridge) GetKeysignParty(vaultPubKey common.PubKey) (common.PubKeys, error) {
	p := fmt.Sprintf(SignerMembershipEndpoint, vaultPubKey.String())
	result, _, err := b.getWithPath(p)
	if err != nil {
		return common.PubKeys{}, fmt.Errorf("fail to get key sign party from thorchain: %w", err)
	}
	var keys common.PubKeys
	if err := json.Unmarshal(result, &keys); err != nil {
		return common.PubKeys{}, fmt.Errorf("fail to unmarshal result to pubkeys:%w", err)
	}
	return keys, nil
}

// IsCatchingUp returns bool for if thorchain is catching up to the rest of the
// nodes. Returns yes, if it is, false if it is caught up.
func (b *ThorchainBridge) IsCatchingUp() (bool, error) {
	uri := url.URL{
		Scheme: "http",
		Host:   b.cfg.ChainRPC,
		Path:   StatusEndpoint,
	}

	body, _, err := b.get(uri.String())
	if err != nil {
		return false, fmt.Errorf("failed to get status data: %w", err)
	}

	var resp struct {
		Result struct {
			SyncInfo struct {
				CatchingUp bool `json:"catching_up"`
			} `json:"sync_info"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return false, fmt.Errorf("failed to unmarshal tendermint status: %w", err)
	}
	return resp.Result.SyncInfo.CatchingUp, nil
}

// WaitToCatchUp wait for thorchain to catch up
func (b *ThorchainBridge) WaitToCatchUp() error {
	for {
		yes, err := b.IsCatchingUp()
		if err != nil {
			return err
		}
		if !yes {
			break
		}
		b.logger.Info().Msg("thorchain is not caught up... waiting...")
		time.Sleep(constants.ThorchainBlockTime)
	}
	return nil
}

// GetAsgards retrieve all the asgard vaults from thorchain
func (b *ThorchainBridge) GetAsgards() (stypes.Vaults, error) {
	buf, s, err := b.getWithPath(AsgardVault)
	if err != nil {
		return nil, fmt.Errorf("fail to get asgard vaults: %w", err)
	}
	if s != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", s)
	}
	var vaults stypes.Vaults
	if err := json.Unmarshal(buf, &vaults); err != nil {
		return nil, fmt.Errorf("fail to unmarshal asgard vaults from json: %w", err)
	}
	return vaults, nil
}

// GetPubKeys retrieve asgard vaults and yggdrasil vaults , and it's relevant smart contracts
func (b *ThorchainBridge) GetPubKeys() ([]PubKeyContractAddressPair, error) {
	buf, s, err := b.getWithPath(PubKeysEndpoint)
	if err != nil {
		return nil, fmt.Errorf("fail to get asgard vaults: %w", err)
	}
	if s != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", s)
	}
	var result stypes.QueryVaultsPubKeys
	if err := json.Unmarshal(buf, &result); err != nil {
		return nil, fmt.Errorf("fail to unmarshal pubkeys: %w", err)
	}
	var addressPairs []PubKeyContractAddressPair
	for _, v := range append(result.Asgard, result.Yggdrasil...) {
		kp := PubKeyContractAddressPair{
			PubKey:         v.PubKey,
			Contracts:      make(map[common.Chain]common.Address),
			CryptonoteData: v.CryptonoteData,
		}
		for _, item := range v.Routers {
			kp.Contracts[item.Chain] = item.Router
		}

		addressPairs = append(addressPairs, kp)
	}
	return addressPairs, nil
}

// PostNetworkFee send network fee message to THORNode
func (b *ThorchainBridge) PostNetworkFee(height int64, chain common.Chain, transactionSize, transactionRate uint64) (common.TxID, error) {
	nodeStatus, err := b.FetchNodeStatus()
	if err != nil {
		return common.BlankTxID, fmt.Errorf("failed to get node status: %w", err)
	}

	if nodeStatus != stypes.NodeStatus_Active {
		return common.BlankTxID, nil
	}
	start := time.Now()
	defer func() {
		b.m.GetHistograms(metrics.SignToThorchainDuration).Observe(time.Since(start).Seconds())
	}()
	msg := stypes.NewMsgNetworkFee(height, chain, transactionSize, transactionRate, b.keys.GetSignerInfo().GetAddress())
	return b.Broadcast(msg)
}

// GetConstants from thornode
func (b *ThorchainBridge) GetConstants() (map[string]int64, error) {
	var result struct {
		Int64Values map[string]int64 `json:"int_64_values"`
	}
	buf, s, err := b.getWithPath(ThorchainConstants)
	if err != nil {
		return nil, fmt.Errorf("fail to get constants: %w", err)
	}
	if s != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", s)
	}
	if err := json.Unmarshal(buf, &result); err != nil {
		return nil, fmt.Errorf("fail to unmarshal to json: %w", err)
	}
	return result.Int64Values, nil
}

// RagnarokInProgress is to query thorchain to check whether ragnarok had been triggered
func (b *ThorchainBridge) RagnarokInProgress() (bool, error) {
	buf, s, err := b.getWithPath(RagnarokEndpoint)
	if err != nil {
		return false, fmt.Errorf("fail to get ragnarok status: %w", err)
	}
	if s != http.StatusOK {
		return false, fmt.Errorf("unexpected status code: %d", s)
	}
	var ragnarok bool
	if err := json.Unmarshal(buf, &ragnarok); err != nil {
		return false, fmt.Errorf("fail to unmarshal ragnarok status: %w", err)
	}
	return ragnarok, nil
}

// GetThorchainVersion retrieve thorchain version
func (b *ThorchainBridge) GetThorchainVersion() (semver.Version, error) {
	buf, s, err := b.getWithPath(ChainVersionEndpoint)
	if err != nil {
		return semver.Version{}, fmt.Errorf("fail to get THORChain version: %w", err)
	}
	if s != http.StatusOK {
		return semver.Version{}, fmt.Errorf("unexpected status code: %d", s)
	}
	var version stypes.QueryVersion
	if err := json.Unmarshal(buf, &version); err != nil {
		return semver.Version{}, fmt.Errorf("fail to unmarshal THORChain version : %w", err)
	}
	return version.Current, nil
}

// GetMimir - get mimir settings
func (b *ThorchainBridge) GetMimir(key string) (int64, error) {
	buf, s, err := b.getWithPath(MimirEndpoint)
	if err != nil {
		return 0, fmt.Errorf("fail to get mimir: %w", err)
	}
	if s != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code: %d", s)
	}
	values := make(map[string]string, 0)
	if err := json.Unmarshal(buf, &values); err != nil {
		return 0, fmt.Errorf("fail to unmarshal mimir: %w", err)
	}
	if val, ok := values[fmt.Sprintf("mimir//%s", strings.ToUpper(key))]; ok {
		return strconv.ParseInt(val, 10, 64)
	}
	return 0, nil
}

// PubKeyContractAddressPair is an entry to map pubkey and contract addresses
type PubKeyContractAddressPair struct {
	PubKey         common.PubKey
	Contracts      map[common.Chain]common.Address
	CryptonoteData string
}

// GetContractAddress retrieve the contract address from asgard
func (b *ThorchainBridge) GetContractAddress() ([]PubKeyContractAddressPair, error) {
	buf, s, err := b.getWithPath(InboundAddressesEndpoint)
	if err != nil {
		return nil, fmt.Errorf("fail to get inbound addresses: %w", err)
	}
	if s != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", s)
	}
	type address struct {
		Chain   common.Chain   `json:"chain"`
		PubKey  common.PubKey  `json:"pub_key"`
		Address common.Address `json:"address"`
		Router  common.Address `json:"router"`
		Halted  bool           `json:"halted"`
	}
	var resp []address
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("fail to unmarshal response: %w", err)
	}
	var result []PubKeyContractAddressPair
	for _, item := range resp {
		exist := false
		for _, pair := range result {
			if item.PubKey.Equals(pair.PubKey) {
				pair.Contracts[item.Chain] = item.Router
				exist = true
				break
			}
		}
		if !exist {
			pair := PubKeyContractAddressPair{
				PubKey:    item.PubKey,
				Contracts: map[common.Chain]common.Address{},
			}
			pair.Contracts[item.Chain] = item.Router
			result = append(result, pair)
		}
	}
	return result, nil
}

// GetPools get pools from THORChain
func (b *ThorchainBridge) GetPools() (stypes.Pools, error) {
	buf, s, err := b.getWithPath(PoolsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("fail to get pools addresses: %w", err)
	}
	if s != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", s)
	}
	var pools stypes.Pools
	if err := json.Unmarshal(buf, &pools); err != nil {
		return nil, fmt.Errorf("fail to unmarshal pools from json: %w", err)
	}
	return pools, nil
}
