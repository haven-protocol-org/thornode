package signer

import (
	"fmt"

	"gitlab.com/thorchain/thornode/x/thorchain/keeper"
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/x/thorchain"
)

type StorageSuite struct{}

var _ = Suite(&StorageSuite{})

func (s *StorageSuite) SetUpSuite(c *C) {
	thorchain.SetupConfigForTest()
}

func (s *StorageSuite) TestStorage(c *C) {
	store, err := NewSignerStore("", "my secret passphrase")
	c.Assert(err, IsNil)

	item := NewTxOutStoreItem(12, types.TxOutItem{Memo: "foo"}, 1)

	c.Assert(store.Set(item), IsNil)
	c.Check(store.Has(item.Key()), Equals, true)

	getItem, err := store.Get(item.Key())
	c.Assert(err, IsNil)
	c.Check(getItem.TxOutItem.Memo, Equals, item.TxOutItem.Memo)

	items := store.List()
	c.Assert(items, HasLen, 1, Commentf("%d", len(items)))

	c.Assert(store.Remove(item), IsNil)
	c.Check(store.Has(item.Key()), Equals, false)

	pk := common.PubKey("tthorpub1addwnpepqfup3y8p0egd7ml7vrnlxgl3wvnp89mpn0tjpj0p2nm2gh0n9hlrvrtylay")

	spent := NewTxOutStoreItem(10, types.TxOutItem{Chain: common.BNBChain, VaultPubKey: pk, Memo: "spent"}, 0)
	spent.Status = TxSpent
	items = []TxOutStoreItem{
		NewTxOutStoreItem(12, types.TxOutItem{Chain: common.BTCChain, VaultPubKey: pk, Memo: "foo"}, 0),
		NewTxOutStoreItem(12, types.TxOutItem{Chain: common.BNBChain, VaultPubKey: pk, Memo: "bar"}, 1),
		NewTxOutStoreItem(13, types.TxOutItem{Chain: common.BNBChain, VaultPubKey: pk, Memo: "baz"}, 2),
		NewTxOutStoreItem(10, types.TxOutItem{Chain: common.BTCChain, VaultPubKey: pk, Memo: "boo"}, 3),
		spent,
	}

	c.Assert(store.Batch(items), IsNil)
	items = store.List()
	c.Assert(items, HasLen, 4)
	c.Check(items[0].TxOutItem.Memo, Equals, "boo")
	c.Check(items[1].TxOutItem.Memo, Equals, "bar", Commentf("%s", items[1].TxOutItem.Memo))
	c.Check(items[2].TxOutItem.Memo, Equals, "foo", Commentf("%s", items[2].TxOutItem.Memo))
	c.Check(items[3].TxOutItem.Memo, Equals, "baz")

	ordered := store.OrderedLists()
	c.Assert(ordered, HasLen, 2, Commentf("%+v", ordered))
	c.Check(ordered[fmt.Sprintf("BTC-%s", pk.String())][0].TxOutItem.Memo, Equals, "boo")
	c.Check(ordered[fmt.Sprintf("BTC-%s", pk.String())][1].TxOutItem.Memo, Equals, "foo", Commentf("%s", items[1].TxOutItem.Memo))
	c.Check(ordered[fmt.Sprintf("BNB-%s", pk.String())][0].TxOutItem.Memo, Equals, "bar", Commentf("%s", items[2].TxOutItem.Memo))
	c.Check(ordered[fmt.Sprintf("BNB-%s", pk.String())][1].TxOutItem.Memo, Equals, "baz")

	c.Check(store.Close(), IsNil)
}

func (s *StorageSuite) TestKey(c *C) {
	item1 := NewTxOutStoreItem(12, types.TxOutItem{Memo: "foo"}, 1)
	item2 := NewTxOutStoreItem(12, types.TxOutItem{Memo: "foo"}, 1)
	item3 := NewTxOutStoreItem(1222, types.TxOutItem{Memo: "foo"}, 3)
	item4 := NewTxOutStoreItem(12, types.TxOutItem{Memo: "bar"}, 4)
	c.Check(item1.Key(), Equals, item2.Key())
	c.Check(item1.Key(), Not(Equals), item3.Key())
	c.Check(item1.Key(), Not(Equals), item4.Key())

	item1.Status = TxSpent
	c.Check(item1.Key(), Equals, item2.Key())
}
func (s *StorageSuite) TestSetSigned(c *C) {
	store, err := NewSignerStore("", "my secret passphrase")
	c.Assert(err, IsNil)
	hash := keeper.GetRandomTxHash().String()
	c.Assert(store.SetSigned(hash), IsNil)
	c.Assert(store.HasSigned(hash), Equals, true)
	newHash := keeper.GetRandomTxHash().String()
	c.Assert(store.HasSigned(newHash), Equals, false)
}
