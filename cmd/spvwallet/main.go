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
		err := start.Execute([]string{"defaultSettings"})
		if err != nil {
			fmt.Printf("spvwallet start failed: %s\n", err)
			os.Exit(1)
		}
	} else {
		_, err := parser.AddCommand("start",
			"start the wallet",
			"The start command starts the wallet daemon",
			&start)
		if err != nil {
			fmt.Printf("spvwallet add start command failed: %s\n", err)
			os.Exit(1)
		}

		_, err = parser.AddCommand("version",
			"print the version number",
			"Print the version number and exit",
			&version)
		if err != nil {
			fmt.Printf("spvwallet add version command failed: %s\n", err)
			os.Exit(1)
		}

		err = cli.SetupCli(parser)
		if err != nil {
			fmt.Printf("spvwallet add commands failed: %s\n", err)
			os.Exit(1)
		}

		if _, err = parser.Parse(); err != nil {
			fmt.Printf("spvwallet parse flag failed: %s\n", err)
			os.Exit(1)
		}
	}
}
