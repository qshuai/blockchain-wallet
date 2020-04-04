package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/jessevdk/go-flags"
	spvwallet "github.com/qshuai/blockchain-wallet"
	"github.com/qshuai/blockchain-wallet/cli"
)

var parser = flags.NewParser(nil, flags.Default)

var start Start
var version Version
var wallet *spvwallet.SPVWallet

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			fmt.Println("spvwallet shutting down...")
			wallet.Close()
			os.Exit(1)
		}
	}()

	if len(os.Args) == 1 {
		start.Gui = true
		start.Execute([]string{"defaultSettings"})
	} else {
		parser.AddCommand("start",
			"start the wallet",
			"The start command starts the wallet daemon",
			&start)
		parser.AddCommand("version",
			"print the version number",
			"Print the version number and exit",
			&version)
		cli.SetupCli(parser)
		if _, err := parser.Parse(); err != nil {
			os.Exit(1)
		}
	}
}
