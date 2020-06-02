package keeperv1

import (
	. "gopkg.in/check.v1"
)

type KeeperTxInSuite struct{}

var _ = Suite(&KeeperTxInSuite{})

func (s *KeeperTxInSuite) TestTxInVoter(c *C) {
	ctx, k := setupKeeperForTest(c)

	tx := GetRandomTx()
	voter := NewObservedTxVoter(
		tx.ID,
		ObservedTxs{NewObservedTx(tx, 12, GetRandomPubKey())},
	)

	k.SetObservedTxInVoter(ctx, voter)
	voter, err := k.GetObservedTxInVoter(ctx, voter.TxID)
	c.Assert(err, IsNil)
	c.Check(voter.TxID.Equals(tx.ID), Equals, true)

	voterOut, err := k.GetObservedTxOutVoter(ctx, voter.TxID)
	c.Assert(err, IsNil)
	c.Assert(voterOut.TxID.Equals(tx.ID), Equals, true)
	c.Assert(voterOut.Tx.IsEmpty(), Equals, true)

	// ensure that if the voter doesn't exist, we DON'T error
	tx = GetRandomTx()
	voter, err = k.GetObservedTxInVoter(ctx, tx.ID)
	c.Assert(err, IsNil)
	c.Check(voter.TxID.Equals(tx.ID), Equals, true)
}