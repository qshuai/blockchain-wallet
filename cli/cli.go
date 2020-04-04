package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/OpenBazaar/jsonpb"
	"github.com/btcsuite/btcd/wire"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/jessevdk/go-flags"
	spvwallet "github.com/qshuai/blockchain-wallet"
	"github.com/qshuai/blockchain-wallet/api"
	"github.com/qshuai/blockchain-wallet/api/pb"
	"google.golang.org/grpc"
)

func SetupCli(parser *flags.Parser) {
	// Add commands to parser
	parser.AddCommand("stop",
		"stop the wallet",
		"The stop command disconnects from peers and shuts down the wallet",
		&stop)
	parser.AddCommand("currentaddress",
		"get the current bitcoin address",
		"Returns the first unused address in the keychain\n\n"+
			"Args:\n"+
			"1. purpose       (string default=external) The purpose for the address. Can be external for receiving from outside parties or internal for example, for change.\n\n"+
			"Examples:\n"+
			"> spvwallet currentaddress\n"+
			"1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS\n"+
			"> spvwallet currentaddress internal\n"+
			"18zAxgfKx4NuTUGUEuB8p7FKgCYPM15DfS\n",
		&currentAddress)
	parser.AddCommand("newaddress",
		"get a new bitcoin address",
		"Returns a new unused address in the keychain. Use caution when using this function as generating too many new addresses may cause the keychain to extend further than the wallet's lookahead window, meaning it might fail to recover all transactions when restoring from seed. CurrentAddress is safer as it never extends past the lookahead window.\n\n"+
			"Args:\n"+
			"1. purpose       (string default=external) The purpose for the address. Can be external for receiving from outside parties or internal for example, for change.\n\n"+
			"Examples:\n"+
			"> spvwallet newaddress\n"+
			"1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS\n"+
			"> spvwallet newaddress internal\n"+
			"18zAxgfKx4NuTUGUEuB8p7FKgCYPM15DfS\n",
		&newAddress)
	parser.AddCommand("chaintip",
		"return the height of the chain",
		"Returns the height of the best chain of headers",
		&chainTip)
	parser.AddCommand("dumpheaders",
		"print the header database",
		"Prints the header database to stdout."+
			"Args:\n"+
			"1. Path (string) Optional path to the header file\n",
		&dumpheaders)
	parser.AddCommand("balance",
		"get the wallet balance",
		"Returns both the confirmed and unconfirmed balances",
		&balance)
	parser.AddCommand("masterprivatekey",
		"get the wallet's master private key",
		"Returns the bip32 master private key",
		&masterPrivateKey)
	parser.AddCommand("masterpublickey",
		"get the wallet's master public key",
		"Returns the bip32 master public key",
		&masterPublicKey)
	parser.AddCommand("getkey",
		"get a private key",
		"Return the private key for the given address",
		&getKey)
	parser.AddCommand("listaddresses",
		"list all addresses",
		"Returns all addresses currently watched by the wallet",
		&listAddresses)
	parser.AddCommand("listkeys",
		"list all private keys",
		"Returns all private keys currently watched by the wallet",
		&listKeys)
	parser.AddCommand("haskey",
		"does key exist",
		"Returns whether a key for the given address exists in the wallet\n\n"+
			"Args:\n"+
			"1. address       (string) The address to find a key for.\n\n"+
			"Examples:\n"+
			"> spvwallet haskey 1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS\n"+
			"true\n",
		&hasKey)
	parser.AddCommand("transactions",
		"get a list of transactions",
		"Returns a json list of the wallet's transactions",
		&transactions)
	parser.AddCommand("gettransaction",
		"get a specific transaction",
		"Returns json data of a specific transaction\n\n"+
			"Args:\n"+
			"1. txid       (string) A transaction ID to search for.\n\n"+
			"Examples:\n"+
			"> spvwallet gettransaction 190bd83935740b88ebdfe724485f36ca4aa40125a21b93c410e0e191d4e9e0b5\n",
		&getTransaction)
	parser.AddCommand("getfeeperbyte",
		"get the current bitcoin fee",
		"Returns the current network fee per byte for the given fee level.\n\n"+
			"Args:\n"+
			"1. feelevel       (string default=normal) The fee level: economic, normal, priority\n\n"+
			"Examples:\n"+
			"> spvwallet getfeeperbyte\n"+
			"140\n"+
			"> spvwallet getfeeperbyte priority\n"+
			"160\n",
		&getFeePerByte)
	parser.AddCommand("spend",
		"send bitcoins",
		"Send bitcoins to the given address\n\n"+
			"Args:\n"+
			"1. address       (string) The recipient's bitcoin address\n"+
			"2. amount        (integer) The amount to send in satoshi"+
			"3. feelevel      (string default=normal) The fee level: economic, normal, priority\n\n"+
			"Examples:\n"+
			"> spvwallet spend 1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS 1000000\n"+
			"82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c"+
			"> spvwallet spend 1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS 3000000000 priority\n"+
			"82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c",
		&spend)
	parser.AddCommand("bumpfee",
		"bump the tx fee",
		"Bumps the fee on an unconfirmed transaction\n\n"+
			"Args:\n"+
			"1. txid       (string) The transaction ID of the transaction to bump.\n\n"+
			"Examples:\n"+
			"> spvwallet bumpfee 190bd83935740b88ebdfe724485f36ca4aa40125a21b93c410e0e191d4e9e0b5\n"+
			"82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c",
		&bumpFee)
	parser.AddCommand("peers",
		"get info about peers",
		"Returns a list of json data on each connected peer",
		&peers)
	parser.AddCommand("addwatchedscript",
		"add a script to watch",
		"Add a script of bitcoin address to watch\n\n"+
			"Args:\n"+
			"1. script       (string) A hex encoded output script or bitcoin address.\n\n"+
			"Examples:\n"+
			"> spvwallet addwatchedscript 1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS\n"+
			"> spvwallet addwatchedscript 76a914f318374559bf8296228e9c7480578a357081d59988ac\n",
		&addWatchedAddress)
	parser.AddCommand("getconfirmations",
		"get the number of confirmations for a tx",
		"Returns the number of confirmations for the given transaction\n\n"+
			"Args:\n"+
			"1. txid       (string) The transaction ID\n\n"+
			"Examples:\n"+
			"> spvwallet getconfirmations 190bd83935740b88ebdfe724485f36ca4aa40125a21b93c410e0e191d4e9e0b5\n"+
			"6\n",
		&getConfirmations)
	parser.AddCommand("sweepaddress",
		"sweep all coins from an address",
		"Completely empty an address into a different one\n\n"+
			"Args:\n"+
			"1. sweepinfo       (jsonobject) A json obeject containing the required data\n"+
			"{\n"+
			`    "utxos": [`+"\n"+
			"                  {\n"+
			`                      "txid": "id"    (string, required) The transaction id`+"\n"+
			`                      "index": n      (integer, required) The output index`+"\n"+
			`                      "value": n      (integer, required) The output amount in satoshi`+"\n"+
			"                  }\n"+
			"             ],\n"+
			`    "address": "addr",        (string, optional) The address to send the coins to. If omitted a change address from this wallet will be used.`+"\n"+
			`    "key": "key",             (string, required) The private key used to sign. Can be in WIF, Hex, or xPriv format`+"\n"+
			`    "redeemScript": "script", (string, optional) Redeem script if p2sh. Only single key scripts supported a present.`+"\n"+
			`    "feeLevel": "level",      (string, optional default=normal ) The fee level: economic, normal, or priority`+"\n"+
			"}\n\n"+
			"Examples:\n"+
			`> spvwallet sweepaddress "{"utxos":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0, "value": 1000000], "address": "1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS", "key": "KzSg35HS67h4e7NLEywc3gNydjbRjzsyrPH5D7G8rpgv9qQCnb3S", "redeemScript": "1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feeLevel":"priority"}"`+"\n"+
			"12c56cfcdc0249002c2a4b1f7fd957c7149fc45d0e9920594c7c78c17dcc34bd\n\n"+
			`> spvwallet sweepaddress "{"utxos":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0, "value": 1000000], "address": "1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS", "key": "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", "feeLevel":"priority"}"`+"\n"+
			"12c56cfcdc0249002c2a4b1f7fd957c7149fc45d0e9920594c7c78c17dcc34bd\n\n"+
			`> spvwallet sweepaddress "{"utxos":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0, "value": 1000000], "address": "1DxGWC22a46VPEjq8YKoeVXSLzB7BA8sJS", "key": "be93c7096dc03bd495894140ff7fee894fbf6c944980d26f8f1cb12cc54316c7"}"`+"\n"+
			"12c56cfcdc0249002c2a4b1f7fd957c7149fc45d0e9920594c7c78c17dcc34bd\n\n"+
			`> spvwallet sweepaddress "{"utxos":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0, "value": 1000000], "key": "be93c7096dc03bd495894140ff7fee894fbf6c944980d26f8f1cb12cc54316c7"}"`+"\n"+
			"12c56cfcdc0249002c2a4b1f7fd957c7149fc45d0e9920594c7c78c17dcc34bd",
		&sweepAddress)
	parser.AddCommand("resyncblockchain",
		"re-download the chain of headers",
		"Will download all headers from the given height. Try this to uncover missing transasctions\n\n"+
			"Args:\n"+
			"1. timestamp       (RFC3339 formatted timestamp) The starting time for the resync.\n\n"+
			"Examples:\n"+
			"> spvwallet resyncblockchain 2017-10-06T16:00:17Z\n"+
			"> spvwallet resyncblockchain",
		&reSyncBlockchain)
	parser.AddCommand("createmultisigsignature",
		"create a p2sh multisig signature",
		"Create a signature for a p2sh multisig transaction\n\n"+
			"Args:\n"+
			"1. txinfo       (jsonobject) A json obeject containing the required data\n"+
			"{\n"+
			`    "inputs": [`+"\n"+
			"                  {\n"+
			`                      "txid": "id"    (string, required) The transaction id`+"\n"+
			`                      "index": n      (integer, required) The output index`+"\n"+
			"                  }\n"+
			"             ],\n"+
			`    "outputs": [`+"\n"+
			"                  {\n"+
			`                      "scriptPubKey": "script"    (string, required) The output script in hex`+"\n"+
			`                      "value": n                  (integer, required) The value to send to this output in satoshi`+"\n"+
			"                  }\n"+
			"             ],\n"+
			`    "key": "key",             (string, required) The private key used to sign. Can be in WIF, Hex, or xPriv format`+"\n"+
			`    "redeemScript": "script", (string, required) Redeem script if p2sh.`+"\n"+
			`    "feePerByte": n,          (integer, required) The fee per byte in satoshis to use.`+"\n"+
			"}\n\n"+
			"Examples:\n"+
			`> spvwallet createmultisigsignature "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "key": "KzSg35HS67h4e7NLEywc3gNydjbRjzsyrPH5D7G8rpgv9qQCnb3S", "redeemScript": "1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feePerByte": 140}"`+"\n"+
			`[{"inputIndex": 0, "signature": "d76206ff0df8ab2c4121bae90c71d9b3a432e8f9c0cc90f66f61dec782bc82983a08c93cd9c660f412ba082f95b11f561276782dfbf4376ff4ca6b2f4ab7b3b0d8ba8b724b0237933a"}]`+"\n\n"+
			`> spvwallet createmultisigsignature "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "key": "be93c7096dc03bd495894140ff7fee894fbf6c944980d26f8f1cb12cc54316c7", "redeemScript": "1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feePerByte": 140}"`+"\n"+
			`[{"inputIndex": 0, "signature": "d76206ff0df8ab2c4121bae90c71d9b3a432e8f9c0cc90f66f61dec782bc82983a08c93cd9c660f412ba082f95b11f561276782dfbf4376ff4ca6b2f4ab7b3b0d8ba8b724b0237933a"}]`+"\n\n"+
			`> spvwallet createmultisigsignature "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "key": "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", "redeemScript": "1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feePerByte": 140}"`+"\n"+
			`[{"inputIndex": 0, "signature": "d76206ff0df8ab2c4121bae90c71d9b3a432e8f9c0cc90f66f61dec782bc82983a08c93cd9c660f412ba082f95b11f561276782dfbf4376ff4ca6b2f4ab7b3b0d8ba8b724b0237933a"}]`+"\n\n",
		&createMultisigSignature)
	parser.AddCommand("multisign",
		"combine multisig signatures",
		"Create a signed 2 of 3 p2sh transaction from two signatures and optionally broadcast\n\n"+
			"Args:\n"+
			"1. txinfo       (jsonobject) A json obeject containing the required data\n"+
			"{\n"+
			`    "inputs": [`+"\n"+
			"                  {\n"+
			`                      "txid": "id"    (string, required) The transaction id`+"\n"+
			`                      "index": n      (integer, required) The output index`+"\n"+
			"                  }\n"+
			"             ],\n"+
			`    "outputs": [`+"\n"+
			"                  {\n"+
			`                      "scriptPubKey": "script"    (string, required) The output script in hex`+"\n"+
			`                      "value": n                  (integer, required) The value to send to this output in satoshi`+"\n"+
			"                  }\n"+
			"             ],\n"+
			`    "sig1": [`+"\n"+
			"                  {\n"+
			`                      "index": n          (integer, required) The input index for signature 1`+"\n"+
			`                      "signature": "sig"  (string, required) The hex encoded signature`+"\n"+
			"                  },\n"+
			"             ],\n"+
			`    "sig2": [`+"\n"+
			"                  {\n"+
			`                      "index": n          (integer, required) The input index for signature 2`+"\n"+
			`                      "signature": "sig"  (string, required) The hex encoded signature`+"\n"+
			"                  },\n"+
			"             ],\n"+
			`    "redeemScript": "script", (string, required) Redeem script if p2sh.`+"\n"+
			`    "feePerByte": n,          (integer, required) The fee per byte in satoshis to use.`+"\n"+
			`    "broadcast": b,           (bool, optional default=false) Broadcast the resulting tx to the network.`+"\n"+
			"}\n\n"+
			"Examples:\n"+
			`> spvwallet multisign "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "sig1": [{"inputIndex": 0, "signature": "d76206ff0df8ab2c4121bae90c71d9b3a432e8f9c0cc90f66f61dec782bc82983a08c93cd9c660f412ba082f95b11f561276782dfbf4376ff4ca6b2f4ab7b3b0d8ba8b724b0237933a"}], "sig2": [{"inputIndex": 0, "signature": "766c36dea732e9640868155b79703545b6ef129bb0446f9b86ac7cad775229ef41ac95543bf488ed42c5b82ffc14d7248136e988b1d4c0ea6d56712de139f83815e8974306d267a900"}], redeemScript": "1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feePerByte": 140, "broadcast": true}"`+"\n"+
			`1393c31443b83c47de7def5a9edaf5f88c050e99f166353ed37404937be3099b`+"\n\n"+
			`> spvwallet multisign "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "sig1": [{"inputIndex": 0, "signature": "d76206ff0df8ab2c4121bae90c71d9b3a432e8f9c0cc90f66f61dec782bc82983a08c93cd9c660f412ba082f95b11f561276782dfbf4376ff4ca6b2f4ab7b3b0d8ba8b724b0237933a"}], "sig2": [{"inputIndex": 0, "signature": "766c36dea732e9640868155b79703545b6ef129bb0446f9b86ac7cad775229ef41ac95543bf488ed42c5b82ffc14d7248136e988b1d4c0ea6d56712de139f83815e8974306d267a900"}], "redeemScript": "1f6eb0660aab25ffe35978e7cb6e31bf40e1cceaf29c7f4f118cd2d76c2088237cb33c75510b8be669d90c01b0c394477690ff9c8388bcec4d71c3855fa50beb", "feePerByte": 140, "broadcast": false}"`+"\n"+
			`010000000100357d084478aa6beba8ca59de331e9bd725d23c3eaf7de0e5167801582a585f040000006b483045022100897aba7833d46a519c1f46694e053be8fdeae32125acd764c54c97ac6856d6f802201ff0e693055e39b16151b4da2a61f8dbb3948c08107b68a4b484dc7359de5b350121026a9dc92c93988750560fb46885fe549251c664e63545889367f5db183637f966ffffffff02a4857902000000001976a9143f2fe0d76898ef6c23b2b2a2892d763e0602bc4288acbd8b7349000000001976a914cc61ffeae5c6673caaaff5c0b06af395c8edc9ad88ac00000000`+"\n\n",
		&multisign)
	parser.AddCommand("estimatefee",
		"estimate the fee for a tx",
		"Given a transaction estimate what fee it will cost in satoshis\n\n"+
			"Args:\n"+
			"1. txinfo       (jsonobject) A json obeject containing the required data\n"+
			"{\n"+
			`    "inputs": [`+"\n"+
			"                  {\n"+
			`                      "txid": "id"    (string, required) The transaction id`+"\n"+
			`                      "index": n      (integer, required) The output index`+"\n"+
			"                  }\n"+
			"             ],\n"+
			`    "outputs": [`+"\n"+
			"                  {\n"+
			`                      "scriptPubKey": "script"    (string, required) The output script in hex`+"\n"+
			`                      "value": n                  (integer, required) The value to send to this output in satoshi`+"\n"+
			"                  }\n"+
			"             ],\n"+
			`    "feePerByte": n,          (integer, required) The fee per byte in satoshis to use.`+"\n"+
			"}\n\n"+
			"Examples:\n"+
			`> spvwallet estimatefee "{"inputs":["txid": "82bfd45f3564e0b5166ab9ca072200a237f78499576e9658b20b0ccd10ff325c", "index": 0], "outputs":["scriptPubKey": "76a914f318374559bf8296228e9c7480578a357081d59988ac", "value": 1000000], "feePerByte": 140}"`+"\n"+
			"18500\n",
		&estimateFee)
}

func newGRPCClient() (pb.APIClient, *grpc.ClientConn, error) {
	// Set up a connection to the server.
	conn, err := grpc.Dial(api.Addr, grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}
	client := pb.NewAPIClient(conn)
	return client, conn, nil
}

type Stop struct{}

var stop Stop

func (x *Stop) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	client.Stop(context.Background(), &pb.Empty{})
	return nil
}

type CurrentAddress struct{}

var currentAddress CurrentAddress

func (x *CurrentAddress) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	var purpose pb.KeyPurpose
	userSelection := ""
	if len(args) > 0 {
		userSelection = args[0]
	}
	switch strings.ToLower(userSelection) {
	case "internal":
		purpose = pb.KeyPurpose_INTERNAL
	case "external":
		purpose = pb.KeyPurpose_EXTERNAL
	default:
		purpose = pb.KeyPurpose_EXTERNAL
	}
	resp, err := client.CurrentAddress(context.Background(), &pb.KeySelection{purpose})
	if err != nil {
		return err
	}
	fmt.Println(resp.Addr)
	return nil
}

type NewAddress struct{}

var newAddress NewAddress

func (x *NewAddress) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	var purpose pb.KeyPurpose
	userSelection := ""
	if len(args) > 0 {
		userSelection = args[0]
	}
	switch strings.ToLower(userSelection) {
	case "internal":
		purpose = pb.KeyPurpose_INTERNAL
	case "external":
		purpose = pb.KeyPurpose_EXTERNAL
	default:
		purpose = pb.KeyPurpose_EXTERNAL
	}
	resp, err := client.NewAddress(context.Background(), &pb.KeySelection{purpose})
	if err != nil {
		return err
	}
	fmt.Println(resp.Addr)
	return nil
}

type ChainTip struct{}

var chainTip ChainTip

func (x *ChainTip) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := client.ChainTip(context.Background(), &pb.Empty{})
	if err != nil {
		return err
	}
	fmt.Println(resp.Height)
	return nil
}

type Balance struct{}

var balance Balance

func (x *Balance) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := client.Balance(context.Background(), &pb.Empty{})
	if err != nil {
		return err
	}
	type ret struct {
		Confirmed   uint64 `json:"confirmed"`
		Unconfirmed uint64 `json:"unconfirmed"`
	}
	out, err := json.MarshalIndent(&ret{resp.Confirmed, resp.Unconfirmed}, "", "    ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

type MasterPrivateKey struct{}

var masterPrivateKey MasterPrivateKey

func (x *MasterPrivateKey) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := client.MasterPrivateKey(context.Background(), &pb.Empty{})
	if err != nil {
		return err
	}
	fmt.Println(resp.Key)
	return nil
}

type MasterPublicKey struct{}

var masterPublicKey MasterPublicKey

func (x *MasterPublicKey) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := client.MasterPublicKey(context.Background(), &pb.Empty{})
	if err != nil {
		return err
	}
	fmt.Println(resp.Key)
	return nil
}

type HasKey struct{}

var hasKey HasKey

func (x *HasKey) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(args) <= 0 {
		return errors.New("Bitcoin address is required")
	}
	resp, err := client.HasKey(context.Background(), &pb.Address{args[0]})
	if err != nil {
		return err
	}
	fmt.Println(resp.Bool)
	return nil
}

type Transactions struct{}

var transactions Transactions

func (x *Transactions) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := client.Transactions(context.Background(), &pb.Empty{})
	if err != nil {
		return err
	}
	chainTip, err := client.ChainTip(context.Background(), &pb.Empty{})
	if err != nil {
		return err
	}
	type Tx struct {
		Txid          string    `json:"txid"`
		Value         int64     `json:"value"`
		Status        string    `json:"status"`
		Timestamp     time.Time `json:"timestamp"`
		Confirmations int32     `json:"confirmations"`
		Height        int32     `json:"height"`
		WatchOnly     bool      `json:"watchOnly"`
	}
	var txns []Tx
	for _, tx := range resp.Transactions {
		var confirmations int32
		var status string
		confs := int32(chainTip.Height) - tx.Height + 1
		if tx.Height <= 0 {
			confs = tx.Height
		}
		ts := time.Unix(int64(tx.Timestamp.Seconds), int64(tx.Timestamp.Nanos))
		switch {
		case confs < 0:
			status = "DEAD"
		case confs == 0 && time.Since(ts) <= time.Hour*6:
			status = "UNCONFIRMED"
		case confs == 0 && time.Since(ts) > time.Hour*6:
			status = "STUCK"
		case confs > 0 && confs < 7:
			status = "PENDING"
			confirmations = confs
		case confs > 6:
			status = "CONFIRMED"
			confirmations = confs
		}
		t := Tx{
			Txid:          tx.Txid,
			Value:         tx.Value,
			Height:        tx.Height,
			WatchOnly:     tx.WatchOnly,
			Timestamp:     ts,
			Status:        status,
			Confirmations: confirmations,
		}
		txns = append(txns, t)
	}
	formatted, err := json.MarshalIndent(txns, "", "    ")
	if err != nil {
		return err
	}
	fmt.Println(string(formatted))
	return nil
}

type GetTransaction struct{}

var getTransaction GetTransaction

func (x *GetTransaction) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(args) <= 0 {
		return errors.New("Txid is required")
	}
	resp, err := client.GetTransaction(context.Background(), &pb.Txid{args[0]})
	if err != nil {
		return err
	}
	chainTip, err := client.ChainTip(context.Background(), &pb.Empty{})
	if err != nil {
		return err
	}
	type Tx struct {
		Txid          string    `json:"txid"`
		Value         int64     `json:"value"`
		Status        string    `json:"status"`
		Timestamp     time.Time `json:"timestamp"`
		Confirmations int32     `json:"confirmations"`
		Height        int32     `json:"height"`
		WatchOnly     bool      `json:"watchOnly"`
	}
	var confirmations int32
	var status string
	confs := int32(chainTip.Height) - resp.Height + 1
	if resp.Height <= 0 {
		confs = resp.Height
	}
	ts := time.Unix(int64(resp.Timestamp.Seconds), int64(resp.Timestamp.Nanos))
	switch {
	case confs < 0:
		status = "DEAD"
	case confs == 0 && time.Since(ts) <= time.Hour*6:
		status = "UNCONFIRMED"
	case confs == 0 && time.Since(ts) > time.Hour*6:
		status = "STUCK"
	case confs > 0 && confs < 7:
		status = "PENDING"
		confirmations = confs
	case confs > 6:
		status = "CONFIRMED"
		confirmations = confs
	}
	t := Tx{
		Txid:          resp.Txid,
		Value:         resp.Value,
		Height:        resp.Height,
		WatchOnly:     resp.WatchOnly,
		Timestamp:     ts,
		Status:        status,
		Confirmations: confirmations,
	}
	formatted, err := json.MarshalIndent(t, "", "    ")
	if err != nil {
		return err
	}
	fmt.Println(string(formatted))
	return nil
}

type GetFeePerByte struct{}

var getFeePerByte GetFeePerByte

func (x *GetFeePerByte) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	var feeLevel pb.FeeLevel
	userSelection := ""
	if len(args) > 0 {
		userSelection = args[0]
	}
	switch strings.ToLower(userSelection) {
	case "economic":
		feeLevel = pb.FeeLevel_ECONOMIC
	case "normal":
		feeLevel = pb.FeeLevel_NORMAL
	case "priority":
		feeLevel = pb.FeeLevel_PRIORITY
	default:
		feeLevel = pb.FeeLevel_NORMAL
	}
	resp, err := client.GetFeePerByte(context.Background(), &pb.FeeLevelSelection{feeLevel})
	if err != nil {
		return err
	}
	fmt.Println(resp.Fee)
	return nil
}

type Spend struct{}

var spend Spend

func (x *Spend) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	var feeLevel pb.FeeLevel
	userSelection := ""
	if len(args) > 2 {
		userSelection = args[2]
	}
	if len(args) < 2 {
		return errors.New("Address and amount are required")
	}
	switch strings.ToLower(userSelection) {
	case "economic":
		feeLevel = pb.FeeLevel_ECONOMIC
	case "normal":
		feeLevel = pb.FeeLevel_NORMAL
	case "priority":
		feeLevel = pb.FeeLevel_PRIORITY
	default:
		feeLevel = pb.FeeLevel_NORMAL
	}
	amt, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	resp, err := client.Spend(context.Background(), &pb.SpendInfo{args[0], uint64(amt), feeLevel})
	if err != nil {
		return err
	}
	fmt.Println(resp.Hash)
	return nil
}

type BumpFee struct{}

var bumpFee BumpFee

func (x *BumpFee) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(args) <= 0 {
		return errors.New("Txid is required")
	}
	resp, err := client.BumpFee(context.Background(), &pb.Txid{args[0]})
	if err != nil {
		return err
	}
	fmt.Println(resp.Hash)
	return nil
}

type Peers struct{}

var peers Peers

func (x *Peers) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := client.Peers(context.Background(), &pb.Empty{})
	if err != nil {
		return err
	}
	type peer struct {
		Address         string    `json:"address"`
		BytesSent       uint64    `json:"bytesSent"`
		BytesReceived   uint64    `json:"bytesReceived"`
		Connected       bool      `json:"connected"`
		ID              int32     `json:"id"`
		LastBlock       int32     `json:"lastBlock"`
		ProtocolVersion uint32    `json:"protocolVersion"`
		Services        string    `json:"services"`
		UserAgent       string    `json:"userAgent"`
		TimeConnected   time.Time `json:"timeConnected"`
	}
	var peers []peer
	for _, p := range resp.Peers {
		pi := peer{
			Address:         p.Address,
			BytesSent:       p.BytesSent,
			BytesReceived:   p.BytesReceived,
			Connected:       p.Connected,
			ID:              p.ID,
			LastBlock:       p.LastBlock,
			ProtocolVersion: p.ProtocolVersion,
			Services:        p.Services,
			UserAgent:       p.UserAgent,
			TimeConnected:   time.Unix(int64(p.TimeConnected.Seconds), int64(p.TimeConnected.Nanos)),
		}
		peers = append(peers, pi)
	}
	out, err := json.MarshalIndent(peers, "", "    ")
	fmt.Println(string(out))
	return nil
}

type AddWatchedAddress struct{}

var addWatchedAddress AddWatchedAddress

func (x *AddWatchedAddress) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(args) <= 0 {
		return errors.New("Address or script required")
	}
	_, err = client.AddWatchedAddress(context.Background(), &pb.Address{args[0]})
	return err
}

type GetConfirmations struct{}

var getConfirmations GetConfirmations

func (x *GetConfirmations) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(args) <= 0 {
		return errors.New("Txid is required")
	}
	resp, err := client.GetConfirmations(context.Background(), &pb.Txid{args[0]})
	if err != nil {
		return err
	}
	fmt.Println(resp.Confirmations)
	return nil
}

type SweepAddress struct{}

var sweepAddress SweepAddress

func (x *SweepAddress) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(args) <= 0 {
		return errors.New("Sweep data is required")
	}
	sweepInfo := new(pb.SweepInfo)
	if err := jsonpb.UnmarshalString(args[0], sweepInfo); err != nil {
		return err
	}
	resp, err := client.SweepAddress(context.Background(), sweepInfo)
	if err != nil {
		return err
	}
	fmt.Println(resp.Hash)
	return nil
}

type ReSyncBlockchain struct{}

var reSyncBlockchain ReSyncBlockchain

func (x *ReSyncBlockchain) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	var ts *timestamp.Timestamp
	if len(args) <= 0 {
		return errors.New("Txid is required")
	} else {
		t, err := time.Parse(time.RFC3339, args[0])
		if err != nil {
			return err
		}
		ts, err = ptypes.TimestampProto(t)
		if err != nil {
			return err
		}
	}
	_, err = client.ReSyncBlockchain(context.Background(), ts)
	if err != nil {
		return err
	}
	return nil
}

type CreateMultisigSignature struct{}

var createMultisigSignature CreateMultisigSignature

func (x *CreateMultisigSignature) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(args) <= 0 {
		return errors.New("Multisig data is required")
	}
	multsigInfo := new(pb.CreateMultisigInfo)
	if err := jsonpb.UnmarshalString(args[0], multsigInfo); err != nil {
		return err
	}
	resp, err := client.CreateMultisigSignature(context.Background(), multsigInfo)
	if err != nil {
		return err
	}
	type sig struct {
		InputIndex uint32 `json:"inputIndex"`
		Signature  string `json:"signature"`
	}
	var sigs []sig
	for _, s := range resp.Sigs {
		retSig := sig{
			InputIndex: s.Index,
			Signature:  hex.EncodeToString(s.Signature),
		}
		sigs = append(sigs, retSig)
	}
	out, err := json.MarshalIndent(sigs, "", "    ")
	fmt.Println(string(out))
	return nil
}

type Multisign struct{}

var multisign Multisign

func (x *Multisign) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(args) <= 0 {
		return errors.New("Multisig data is required")
	}
	multsignInfo := new(pb.MultisignInfo)
	if err := jsonpb.UnmarshalString(args[0], multsignInfo); err != nil {
		return err
	}
	resp, err := client.Multisign(context.Background(), multsignInfo)
	if err != nil {
		return err
	}
	if multsignInfo.Broadcast {
		r := bytes.NewReader(resp.Tx)
		msgTx := wire.NewMsgTx(1)
		msgTx.BtcDecode(r, 1, wire.WitnessEncoding)
		fmt.Println(msgTx.TxHash().String())
	} else {
		fmt.Println(hex.EncodeToString(resp.Tx))
	}
	return nil
}

type EstimateFee struct{}

var estimateFee EstimateFee

func (x *EstimateFee) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(args) <= 0 {
		return errors.New("Tx data is required")
	}
	estimateFeeData := new(pb.EstimateFeeData)
	if err := jsonpb.UnmarshalString(args[0], estimateFeeData); err != nil {
		return err
	}
	resp, err := client.EstimateFee(context.Background(), estimateFeeData)
	if err != nil {
		return err
	}
	fmt.Println(resp.Fee)
	return nil
}

type DumpHeaders struct{}

var dumpheaders DumpHeaders

func (x *DumpHeaders) Execute(args []string) error {
	if len(args) <= 0 {
		client, conn, err := newGRPCClient()
		if err != nil {
			return err
		}
		defer conn.Close()
		stream, err := client.DumpHeaders(context.Background(), &pb.Empty{})
		if err != nil {
			return err
		}
		for {
			hdr, err := stream.Recv()
			if err != nil {
				return err
			}
			fmt.Println(hdr.Entry)
		}
	} else {
		db, err := spvwallet.NewHeaderDB(args[0])
		if err != nil {
			fmt.Println(err)
		} else {
			db.Print(os.Stdout)
		}
	}
	return nil
}

type GetKey struct{}

var getKey GetKey

func (x *GetKey) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(args) <= 0 {
		return errors.New("Address is required")
	}
	resp, err := client.GetKey(context.Background(), &pb.Address{args[0]})
	if err != nil {
		return err
	}
	fmt.Println(resp.Key)
	return nil
}

type ListAddresses struct{}

var listAddresses ListAddresses

func (x *ListAddresses) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := client.ListAddresses(context.Background(), &pb.Empty{})
	if err != nil {
		return err
	}
	for _, addr := range resp.Addresses {
		fmt.Println(addr.Addr)
	}
	return nil
}

type ListKeys struct{}

var listKeys ListKeys

func (x *ListKeys) Execute(args []string) error {
	client, conn, err := newGRPCClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := client.ListKeys(context.Background(), &pb.Empty{})
	if err != nil {
		return err
	}
	for _, key := range resp.Keys {
		fmt.Println(key.Key)
	}
	return nil
}
