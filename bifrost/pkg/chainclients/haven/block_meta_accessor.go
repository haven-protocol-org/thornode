package haven

// BlockMetaAccessor define methods need to access block meta storage
type BlockMetaAccessor interface {
	GetBlockMetas() ([]*BlockMeta, error)
	GetBlockMeta(height int64) (*BlockMeta, error)
	SaveBlockMeta(height int64, blockMeta *BlockMeta) error
	PruneBlockMeta(height int64) error
	//TODO: these functions doesn't exist in the eth client but exist in btc
	// UpsertTransactionFee(fee float64, vSize int32) error
	// GetTransactionFee() (float64, int32, error)
}
