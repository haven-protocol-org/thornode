package constants

// NewConstantValue010 get new instance of ConstantValue010
func NewConstantValue010() *ConstantVals {
	return &ConstantVals{
		int64values: map[ConstantName]int64{
			EmissionCurve:                 6,
			BlocksPerYear:                 6311390,
			IncentiveCurve:                100,                // configures incentive pendulum
			OutboundTransactionFee:        2_000000,           // A 0.02 Rune fee on all swaps and withdrawals
			NativeTransactionFee:          2_000000,           // A 0.02 Rune fee on all on chain txs
			PoolCycle:                     51840,              // Make a pool available every 3 days
			MinRunePoolDepth:              10000_00000000,     // minimum rune pool depth to be an available pool
			MaxAvailablePools:             100,                // maximum number of available pools
			MinimumNodesForYggdrasil:      6,                  // No yggdrasil pools if THORNode have less than 6 active nodes
			MinimumNodesForBFT:            4,                  // Minimum node count to keep network running. Below this, Ragnarök is performed.
			DesiredValidatorSet:           90,                 // desire validator set
			AsgardSize:                    30,                 // desired node operators in an asgard vault
			FundMigrationInterval:         360,                // number of blocks THORNode will attempt to move funds from a retiring vault to an active one
			ChurnInterval:                 51840,              // How many blocks THORNode try to rotate validators
			ChurnRetryInterval:            720,                // How many blocks until we retry a churn (only if we haven't had a successful churn in ChurnInterval blocks
			BadValidatorRedline:           3,                  // redline multiplier to find a multitude of bad actors
			BadValidatorRate:              51840,              // rate to mark a validator to be rotated out for bad behavior
			OldValidatorRate:              51840,              // rate to mark a validator to be rotated out for age
			LackOfObservationPenalty:      2,                  // add two slash point for each block where a node does not observe
			SigningTransactionPeriod:      300,                // how many blocks before a request to sign a tx by yggdrasil pool, is counted as delinquent.
			DoubleSignMaxAge:              24,                 // number of blocks to limit double signing a block
			MinimumBondInRune:             1_000_000_00000000, // 1 million rune
			FailKeygenSlashPoints:         720,                // slash for 720 blocks , which equals 1 hour
			FailKeysignSlashPoints:        2,                  // slash for 2 blocks
			LiquidityLockUpBlocks:         0,                  // the number of blocks LP can withdraw after their liquidity
			ObserveSlashPoints:            1,                  // the number of slashpoints for making an observation (redeems later if observation reaches consensus
			ObservationDelayFlexibility:   10,                 // number of blocks of flexibility for a validator to get their slash points taken off for making an observation
			YggFundLimit:                  50,                 // percentage of the amount of funds a ygg vault is allowed to have.
			JailTimeKeygen:                720 * 6,            // blocks a node account is jailed for failing to keygen. DO NOT drop below tss timeout
			JailTimeKeysign:               60,                 // blocks a node account is jailed for failing to keysign. DO NOT drop below tss timeout
			CliTxCost:                     1_00000000,         // amount of bonded rune to move to the reserve when using a cli command
			MinSwapsPerBlock:              10,                 // process all swaps if queue is less than this number
			MaxSwapsPerBlock:              100,                // max swaps to process per block
			VirtualMultSynths:             2,                  // pool depth multiplier for synthetic swaps
			MinSlashPointsForBadValidator: 100,                // The minimum slash point
		},
		boolValues: map[ConstantName]bool{
			StrictBondLiquidityRatio: true,
		},
		stringValues: map[ConstantName]string{
			DefaultPoolStatus: "Staged",
		},
	}
}
