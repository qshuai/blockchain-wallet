package main

import (
	"fmt"
	"os"

	"github.com/btcsuite/btcd/chaincfg"
	spvwallet "github.com/qshuai/blockchain-wallet"
	"github.com/qshuai/blockchain-wallet/db"
	"github.com/sirupsen/logrus"
)

func main() {
	// Create a new config
	config := spvwallet.NewDefaultConfig()

	// Make the logging a little prettier
	config.Logger = logrus.Logger{
		Out: os.Stdout,
	}

	// Use testnet
	config.Params = &chaincfg.TestNet3Params

	// Select wallet datastore
	sqliteDatastore, _ := db.Create(config.DataDir)
	config.DB = sqliteDatastore

	// Create the wallet
	wallet, err := spvwallet.NewSPVWallet(config)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Start it!
	wallet.Start()
}
