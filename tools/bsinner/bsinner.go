package main

import (
	"flag"
	"log"

	"gitlab.com/thorchain/bepswap/thornode/test/smoke"
)

// smoke test run a json config file that is a series of transaction and expected results.
func main() {
	apiAddr := flag.String("a", "testnet-dex.binance.org", "Binance API Address.")
	faucetKey := flag.String("f", "", "The faucet private key.")
	poolKey := flag.String("p", "", "The pool private key.")
	environment := flag.String("e", "stage", "The environment to use [local|staging|develop|production].")
	config := flag.String("c", "", "Path to the config file.")
	network := flag.Int("n", 0, "The network to use.")
	logFile := flag.String("l", "/tmp/smoke.json", "The path to the log file [/tmp/smoke.json].")
	debug := flag.Bool("d", false, "Enable debugging of the Binance transactions.")
	flag.Parse()

	if *faucetKey == "" {
		log.Fatal("No faucet key set!")
	}

	if *poolKey == "" {
		log.Fatal("No pool key set!")
	}

	if *config == "" {
		log.Fatal("No config file provided!")
	}

	s := smoke.NewSmoke(*apiAddr, *faucetKey, *poolKey, *environment, *config, *network, *logFile, *debug)
	s.Run()
}