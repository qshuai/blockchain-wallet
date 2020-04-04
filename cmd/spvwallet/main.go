package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/qshuai/blockchain-wallet/cmd/spvwallet/cmd"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	version = "0.1.0"
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			fmt.Println("spvwallet shutting down...")
			cmd.Shutdown()
			os.Exit(1)
		}
	}()

	var rootCmd = &cobra.Command{
		Use:   "spvwallet [flags] command",
		Short: "A multi-cryptocurrency wallet written in Go.",
		Long: `spvwallet is a forked repository from OpenBazaar/spvwallet(https://github.com/OpenBazaar/spvwallet).
As the origin repository, spvwallet is a spv node that will sync block head and merkletree message.
spvwallet will support Bitcoin Core, Bitcoin Cash, Bitcoin BSV, Litecoin, Ethereum and so on.`,
	}

	var (
		datadir    string
		testnet    bool
		regtest    bool
		mnemonic   string
		startPoint string
		node       string
		tor        bool
		feeApi     string
		feeLevel   string
		isGui      bool
		stdout     bool
	)

	// parse flags
	rootCmd.PersistentFlags().StringVarP(&datadir, "datadir", "d", "", "specify the data directory to be used")
	rootCmd.PersistentFlags().BoolVarP(&testnet, "testnet", "t", false, "use the testnet3 network")
	rootCmd.PersistentFlags().BoolVarP(&regtest, "regtest", "r", false, "use the regtest network")
	rootCmd.PersistentFlags().StringVarP(&mnemonic, "mnemonic", "m", "", "specify a mnemonic seed to use to derive the keychain")
	rootCmd.PersistentFlags().StringVarP(&startPoint, "startpoint", "s", "", "specify the date the seed was created. if omitted the wallet will sync from the oldest checkpoint")
	rootCmd.PersistentFlags().StringVarP(&node, "node", "n", "", "specify a single trusted peer to connect to")
	rootCmd.PersistentFlags().BoolVarP(&tor, "tor", "o", false, "connect via a running Tor daemon")
	rootCmd.PersistentFlags().StringVarP(&feeApi, "fee-api", "a", "", "fee API to use to fetch current fee rates. set as empty string to disable API lookups")
	rootCmd.PersistentFlags().StringVarP(&feeLevel, "fee-level", "f", "140,160,180,2000", "fee rate level")
	rootCmd.PersistentFlags().BoolVarP(&isGui, "gui", "g", false, "launch an experimental GUI")
	rootCmd.PersistentFlags().BoolVarP(&stdout, "stdout", "v", false, "print to standard out")

	rootCmd.AddCommand(
		&cobra.Command{
			Use:   "start",
			Short: "start the wallet",
			Long:  `The start command starts the wallet daemon`,
			Run:   cmd.Start,
		},
		&cobra.Command{
			Use:   "version",
			Short: "print the wallet version",
			Long:  `Print the version number and exit`,
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Printf("spvwallet: %s\n", version)
			},
		},
		&cobra.Command{
			Use:   "stop",
			Short: "stop the wallet",
			Long:  `The stop command disconnects from peers and shuts down the wallet`,
			Run:   cmd.Stop,
		},
		&cobra.Command{
			Use:   "address",
			Short: "get the current bitcoin address",
			Long: `Returns the first unused address in the keychain
			Args:
			1. purpose       (string default=external) The purpose for the address. Can be external for receiving from outside parties or internal for example, for change.
			Examples:
			> spvwallet currentaddress
			1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS
			> spvwallet currentaddress internal
			18zAxgfKx4NuTUGUEuB8p7FKgCYPM15DfS`,
			Run: cmd.Address,
		},
		&cobra.Command{
			Use:   "newaddress",
			Short: "get a new bitcoin address",
			Long: `Returns a new unused address in the keychain. Use caution when using this function as generating too many new addresses may cause the keychain to extend further than the wallet's lookahead window, meaning it might fail to recover all transactions when restoring from seed. CurrentAddress is safer as it never extends past the lookahead window.
			Args:
			1. purpose       (string default=external) The purpose for the address. Can be external for receiving from outside parties or internal for example, for change.
			Examples:
			> spvwallet newaddress
			1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS
			> spvwallet newaddress internal
			18zAxgfKx4NuTUGUEuB8p7FKgCYPM15DfS`,
			Run: cmd.NewAddress,
		},
		&cobra.Command{
			Use:   "chaintip",
			Short: "return the height of the chain",
			Long:  `Returns the height of the best chain of headers`,
			Run:   cmd.ChainTip,
		},
		&cobra.Command{
			Use:   "dumpheaders",
			Short: "print the header database",
			Long:  `Prints the header database to stdout.`,
			Run:   cmd.DumpHeaders,
		},
		&cobra.Command{
			Use:   "balance",
			Short: "get the wallet balance",
			Long:  `Returns both the confirmed and unconfirmed balances`,
			Run:   cmd.Balance,
		},
		&cobra.Command{
			Use:   "masterprivatekey",
			Short: "get the wallet's master private key",
			Long:  `Returns the bip32 master private key`,
			Run:   cmd.MasterPrivateKey,
		},
		&cobra.Command{
			Use:   "masterpublickey",
			Short: "get the wallet's master public key",
			Long:  `Returns the bip32 master public key`,
			Run:   cmd.MasterPublicKey,
		},
		&cobra.Command{
			Use:   "dumpprivatekey",
			Short: "get a private key",
			Long:  `Return the private key for the given address`,
			Run:   cmd.DumpPrivateKey,
		},
		&cobra.Command{
			Use:   "listaddresses",
			Short: "list all addresses",
			Long:  `Returns all addresses currently watched by the wallet`,
			Run:   cmd.ListAddresses,
		},
		&cobra.Command{
			Use:   "listkeys",
			Short: "list all private keys",
			Long:  `Returns all private keys currently watched by the wallet`,
			Run:   cmd.ListPrivateKey,
		},
		&cobra.Command{
			Use:   "haskey",
			Short: "does key exist",
			Long: `Returns whether a key for the given address exists in the wallet
			Args:
			1. address       (string) The address to find a key for.
			Examples:
			> spvwallet haskey 1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS
			true`,
			Run: cmd.HasKey,
		},
		&cobra.Command{
			Use:   "listtransaction",
			Short: "get a list of transactions",
			Long:  `Returns a json list of the wallet's transactions`,
			Run:   cmd.ListTransaction,
		},
		&cobra.Command{
			Use:   "gettransaction",
			Short: "get a specific transaction",
			Long: `Returns json data of a specific transaction
			Args:
			1. txid       (string) A transaction ID to search for.
			Examples:
			> spvwallet gettransaction 190bd83935740b88ebdfe724485f36ca4aa40125a21b93c410e0e191d4e9e0b5`,
			Run: cmd.GetTransaction,
		},
		&cobra.Command{
			Use:   "getfeeperbyte",
			Short: "get the current bitcoin fee",
			Long: `Returns the current network fee per byte for the given fee level.
			Args:
			1. feelevel       (string default=normal) The fee level: economic, normal, priority
			Examples:
			> spvwallet getfeeperbyte
			140
			> spvwallet getfeeperbyte priority`,
			Run: cmd.GetFeePerByte,
		},
		&cobra.Command{
			Use:   "spend",
			Short: "send bitcoins",
			Long: `Send bitcoins to the given address
                    Args:
			        1. address       (string) The recipient's bitcoin address
			        2. amount        (integer) The amount to send in satoshi
			        3. feelevel      (string default=normal) The fee level: economic, normal, priority
			        Examples:
			        > spvwallet spend 1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS 1000000
			        82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c
			        > spvwallet spend 1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS 3000000000 priority
			        82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c`,
			Run: cmd.Spend,
		},
		&cobra.Command{
			Use:   "bumpfee",
			Short: "bump the tx fee",
			Long: `Bumps the fee on an unconfirmed transaction\n\n"+
			        Args:
			        1. txid       (string) The transaction ID of the transaction to bump.
			        Examples:
			        > spvwallet bumpfee 190bd83935740b88ebdfe724485f36ca4aa40125a21b93c410e0e191d4e9e0b5
			        82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c`,
			Run: cmd.BumpFee,
		},
		&cobra.Command{
			Use:   "peers",
			Short: "get info about peers",
			Long:  `Returns a list of json data on each connected peer`,
			Run:   cmd.Peers,
		},
		&cobra.Command{
			Use:   "watchscript",
			Short: "add a script to watch",
			Long: `Add a script of bitcoin address to watch
			Args:
			1. script       (string) A hex encoded output script or bitcoin address.
			Examples:
			> spvwallet addwatchedscript 1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS
			> spvwallet addwatchedscript 76a914f318374559bf8296228e9c7480578a357081d59988ac`,
			Run: cmd.WatchScript,
		},
		&cobra.Command{
			Use:   "getconfirmations",
			Short: "get the number of confirmations for a tx",
			Long: `Returns the number of confirmations for the given transaction
			Args:
			1. txid       (string) The transaction ID
			Examples:
			> spvwallet getconfirmations 190bd83935740b88ebdfe724485f36ca4aa40125a21b93c410e0e191d4e9e0b56`,
			Run: cmd.GetConfirmations,
		},
		&cobra.Command{
			Use:   "sweepaddress",
			Short: "sweep all coins from an address",
			Long: `Completely empty an address into a different one
			Args:
			1. sweepinfo       (jsonobject) A json obeject containing the required data
			{
			    "utxos": [
			                  {
			                      "txid": "id"    (string, required) The transaction id
			                      "index": n      (integer, required) The output index
			                      "value": n      (integer, required) The output amount in satoshi
			                  }
			             ],
			    "address": "addr",        (string, optional) The address to send the coins to. If omitted a change address from this wallet will be used.
			    "key": "key",             (string, required) The private key used to sign. Can be in WIF, Hex, or xPriv format
			    "redeemScript": "script", (string, optional) Redeem script if p2sh. Only single key scripts supported a present.
			    "feeLevel": "level",      (string, optional default=normal ) The fee level: economic, normal, or priority
			}
			Examples:
			> spvwallet sweepaddress "{"utxos":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0, "value": 1000000], "address": "1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS", "key": "KzSg35HS67h4e7NLEywc3gNydjbRjzsyrPH5D7G8rpgv9qQCnb3S", "redeemScript": "1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feeLevel":"priority"}"
			12c56cfcdc0249002c2a4b1f7fd957c7149fc45d0e9920594c7c78c17dcc34bd
			> spvwallet sweepaddress "{"utxos":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0, "value": 1000000], "address": "1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS", "key": "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", "feeLevel":"priority"}"
			12c56cfcdc0249002c2a4b1f7fd957c7149fc45d0e9920594c7c78c17dcc34bd
			> spvwallet sweepaddress "{"utxos":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0, "value": 1000000], "address": "1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS", "key": "be93c7096dc03bd495894140ff7fee894fbf6c944980d26f8f1cb12cc54316c7"}"
			12c56cfcdc0249002c2a4b1f7fd957c7149fc45d0e9920594c7c78c17dcc34bd
			> spvwallet sweepaddress "{"utxos":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0, "value": 1000000], "key": "be93c7096dc03bd495894140ff7fee894fbf6c944980d26f8f1cb12cc54316c7"}"
			12c56cfcdc0249002c2a4b1f7fd957c7149fc45d0e9920594c7c78c17dcc34bd`,
			Run: cmd.SweepAddress,
		},
		&cobra.Command{
			Use:   "resyncblockchain",
			Short: "re-download the chain of headers",
			Long: `Will download all headers from the given height. Try this to uncover missing transasctions
			Args:
			1. timestamp       (RFC3339 formatted timestamp) The starting time for the resync.
			Examples:
			> spvwallet resyncblockchain 2017-10-06T16:00:17Z
			> spvwallet resyncblockchain`,
			Run: cmd.ReSyncBlockchain,
		},
		&cobra.Command{
			Use:   "createmultisigsignature",
			Short: "create a p2sh multisig signature",
			Long: `Create a signature for a p2sh multisig transaction
Args:
1. txinfo       (jsonobject) A json obeject containing the required data
{
    "inputs": [
                  {
                      "txid": "id"    (string, required) The transaction id
                      "index": n      (integer, required) The output index
                  }
             ],
    "outputs": [
                  {
                      "scriptPubKey": "script"    (string, required) The output script in hex
                      "value": n                  (integer, required) The value to send to this output in satoshi
                  }
             ],
    "key": "key",             (string, required) The private key used to sign. Can be in WIF, Hex, or xPriv format
    "redeemScript": "script", (string, required) Redeem script if p2sh.
    "feePerByte": n,          (integer, required) The fee per byte in satoshis to use.
}
Examples:
> spvwallet createmultisigsignature "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "key": KzSg35HS67h4e7NLEywc3gNydjbRjzsyrPH5D7G8rpgv9qQCnb3S", "redeemScript": "1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feePerByte": 140}"
[{"inputIndex": 0, "signature": "d76206ff0df8ab2c4121bae90c71d9b3a432e8f9c0cc90f66f61dec782bc82983a08c93cd9c660f412ba082f95b11f561276782dfbf4376ff4ca6b2f4ab7b3b0d8ba8b724b0237933a"}]
> spvwallet createmultisigsignature "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "key": be93c7096dc03bd495894140ff7fee894fbf6c944980d26f8f1cb12cc54316c7", "redeemScript": "1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feePerByte": 140}"
[{"inputIndex": 0, "signature": "d76206ff0df8ab2c4121bae90c71d9b3a432e8f9c0cc90f66f61dec782bc82983a08c93cd9c660f412ba082f95b11f561276782dfbf4376ff4ca6b2f4ab7b3b0d8ba8b724b0237933a"}]
> spvwallet createmultisigsignature "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "key": xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", "redeemScript": "1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feePerByte": 140}"
[{"inputIndex": 0, "signature": "d76206ff0df8ab2c4121bae90c71d9b3a432e8f9c0cc90f66f61dec782bc82983a08c93cd9c660f412ba082f95b11f561276782dfbf4376ff4ca6b2f4ab7b3b0d8ba8b724b0237933a"}]
`,
			Run: cmd.CreateMultisigSignature,
		},
		&cobra.Command{
			Use:   "multisign",
			Short: "combine multisig signatures",
			Long: `Create a signed 2 of 3 p2sh transaction from two signatures and optionally broadcast
                   Args:
                   1. txinfo       (jsonobject) A json obeject containing the required data
                   {
                       "inputs": [
                   			{
                   				"txid": "id"    (string, required) The transaction id
                                         "index": n      (integer, required) The output index
                   			}
                   		],
                   			"outputs": [
                                     {
                                         "scriptPubKey": "script"    (string, required) The output script in hex
                   			"value": n                  (integer, required) The value to send to this output in satoshi
                                     }
                                ],
                       "sig1": [
                   		{
                   			"index": n          (integer, required) The input index for signature 1
                                         "signature": "sig"  (string, required) The hex encoded signature
                   		},
                   		],
                   			"sig2": [
                                     {
                                         "index": n          (integer, required) The input index for signature 2
                   			"signature": "sig"  (string, required) The hex encoded signature
                                     },
                                ],
                       "redeemScript": "script", (string, required) Redeem script if p2sh.
                   			"feePerByte": n,          (integer, required) The fee per byte in satoshis to use.
                       "broadcast": b,           (bool, optional default=false) Broadcast the resulting tx to the network.
                   		}
                        Examples:
	                    > spvwallet multisign "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "sig1": [{"inputIndex": 0, "signature": d76206ff0df8ab2c4121bae90c71d9b3a432e8f9c0cc90f66f61dec782bc82983a08c93cd9c660f412ba082f95b11f561276782dfbf4376ff4ca6b2f4ab7b3b0d8ba8b724b0237933a"}], "sig2": [{"inputIndex": 0, "signature": 766c36dea732e9640868155b79703545b6ef129bb0446f9b86ac7cad775229ef41ac95543bf488ed42c5b82ffc14d7248136e988b1d4c0ea6d56712de139f83815e8974306d267a900"}], redeemScript": 1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feePerByte": 140, "broadcast": true}"
1393c31443b83c47de7def5a9edaf5f88c050e99f166353ed37404937be3099b
                        > spvwallet multisign "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "sig1": [{"inputIndex": 0, "signature": d76206ff0df8ab2c4121bae90c71d9b3a432e8f9c0cc90f66f61dec782bc82983a08c93cd9c660f412ba082f95b11f561276782dfbf4376ff4ca6b2f4ab7b3b0d8ba8b724b0237933a"}], "sig2": [{"inputIndex": 0, "signature": 766c36dea732e9640868155b79703545b6ef129bb0446f9b86ac7cad775229ef41ac95543bf488ed42c5b82ffc14d7248136e988b1d4c0ea6d56712de139f83815e8974306d267a900"}], "redeemScript": 1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feePerByte": 140, "broadcast": false}"
010000000100357d084478aa6beba8ca59de331e9bd725d23c3eaf7de0e5167801582a585f040000006b483045022100897aba7833d46a519c1f46694e053be8fdeae32125acd764c54c97ac6856d6f802201ff0e693055e39b16151b4da2a61f8dbb3948c08107b68a4b484dc7359de5b350121026a9dc92c93988750560fb46885fe549251c664e63545889367f5db183637f966ffffffff02a4857902000000001976a9143f2fe0d76898ef6c23b2b2a2892d763e0602bc4288acbd8b7349000000001976a914cc61ffeae5c6673caaaff5c0b06af395c8edc9ad88ac00000000`,
			Run: cmd.MultiSign,
		},
		&cobra.Command{
			Use:   "estimatefee",
			Short: "estimate the fee for a tx",
			Long: `Given a transaction estimate what fee it will cost in satoshis
				   Args:
				   1. txinfo       (jsonobject) A json obeject containing the required data
				   {
				       "inputs": [
				                     {
				                         "txid": "id"    (string, required) The transaction id
				                         "index": n      (integer, required) The output index
				                     }
				                ],
				       "outputs": [
				                     {
				                         "scriptPubKey": "script"    (string, required) The output script in hex
				                         "value": n                  (integer, required) The value to send to this output in satoshi
				                     }
				                ],
				       "feePerByte": n,          (integer, required) The fee per byte in satoshis to use.
				   }
				   Examples:
				   > spvwallet estimatefee "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "feePerByte": 140}"
				   18500`,
			Run: cmd.EstimateFee,
		},
	)

	if err := rootCmd.Execute(); err != nil {
		logrus.Errorf("spvwallet start failed: %s", err)
		os.Exit(1)
	}
}
