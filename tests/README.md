# Testing

## Definitions

#### Actors
The smoke tests generate the following `Actors` for executing transactions against the statechain:

##### Bank
The Binance faucet that funds the master account.

##### Master
The master is funded by the bank. The master account then seeds all other actors. There is only a single master account.

##### Admin
An admin is what performs all admin transactions (memos prefixed with `ADMIN:`).

##### User
A user simply performs swaps.

##### Staker
A staker simply stakes funds into the pool or pools.

## Tests

For further information on the tests being run, please see [here](https://docs.google.com/spreadsheets/d/1sLK0FE-s6LInWijqKgxAzQk2RiSDZO1GL58kAD62ch0). The purpose of these tests are simply to determine if the Statechain, and its dependant components, are operating as expected, whenever new code is deployed. 

### Lifecycle

A full smoke test lifecycle is as follows:

* Generate the actors;
* SEED the master with funds from the bank (faucet);
* then SEED the other accounts (admin, user and staker(s));
* then GAS the pool;
* then STAKE;
* then SWAP;
* then END;
* then re-enable the pools;
* then SWEEP all assets back to the bank from the various actors.

Unit tests (where we've broken the SWAPs and STAKEs into their own test definitions) still follow a variant of the above (as we still need to SEED the actors; GAS, END and ENABLE the pool).

### Definitions

The test definitions are all written in JSON and follow a fairly simple format, that should be easy to read.

At the top level we define how many stakers we wish to create as well as our main rules array. 

```json
{
  "staker_count": 2,
  "rules" [...]
}
```

Each rule will have:

```json
{
  {
    "description": "SEED",
    "from": "from",
    "to": ["to"],
    "coins": [..],
    "memo": "MEMO",
    "check": {}
  }
}
```

Where:

* `description` is a simple description to describe the definition,
* `from` is the actor performing the transaction (e.g: `master`, `admin`, `user`, `staker_N` or `pool`),
* `to` is an array of actors the transaction is for (by using an array, we can support multi-send),
* `coins` is an array of coin objects:
```json
{
  "symbol": "BNB",
  "amount": 1.00000000
}
```
* `memo` is the memo to use for the transaction, when broadcasting to Binance
* and `check` defines the rules for validating the transaction (see blow).

#### Validation

After a transaction has been executed, we either check Binance or the Statechain (or sometimes both), to ensure that the resulting balances are inline with our business rules. If this is empty, then the transaction will still be executed, but the result won't be validated.

```json
{
  "target": "from",
  "binance": [...],
  "statechain": {
    "units": 1.00000000,
    "symbol": "BNB",
    "rune": 1.00000000,
    "token": 1.00000000
  }
}
```

Where:

* `target` the target actor Binance wallet to check (only used for checking Binance). This is useful when checking that refunds have been executed correctly,
* `binance` is an array of coin objects (follows the same structure as above)
* and `statechain` is an object that contains the pool `units`, `rune` and `token` balances to check for a given pool (determined by the `symbol` supplied).

### Running the Tests

The tests are all run via `make`.

#### Main test suite

```shell script
make BANK_KEY=<bank key> POOL_KEY=<pool key> ENV=<env> smoke-test-refund
```

#### Individual (Unit) Tests

These are really only intended to be run when debugging locally - e.g.: you wish to generate noise (without running the full suite) to see what the Chain Service or other components within the stack observe/report.

##### Gas

```shell script
make BANK_KEY=<bank key> POOL_KEY=<pool key> ENV=<env> gas
```

##### Seed

```shell script
make BANK_KEY=<bank key> POOL_KEY=<pool key> ENV=<env> seed
```

##### Stake

```shell script
make BANK_KEY=<bank key> POOL_KEY=<pool key> ENV=<env> stake
```

##### Swap

```shell script
make BANK_KEY=<bank key> POOL_KEY=<pool key> ENV=<env> swap
```

For each of the tests you must provide:

* `BANK_KEY` this is the private key of the faucet. Without this, the tests will fail as nothing will be funded,
* `POOL_KEY` this is the private key of the pool that that Statechain Observer is listening on
* and `ENV` is the environment to run the tests against (can be one of `local`, `dev`, `stage` or `prod`).

#### Sweep

While all assets are swept up and returned to the bank (faucet) on completion of the tests, you can manually perform a sweep by running:

```shell script
make MASTER_KEY=<master key> KEY_LIST=<key list> sweep
```

Where:

* `MASTER_KEY` is the private key of the wallet we wish to transfer assets to
* and `KEY_LIST` is a comma-separated list of private keys we wish to sweep up the assets from.