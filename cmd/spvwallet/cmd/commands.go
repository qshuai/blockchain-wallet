package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenBazaar/jsonpb"
	wi "github.com/OpenBazaar/wallet-interface"
	"github.com/asticode/go-astilectron"
	"github.com/atotto/clipboard"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/fatih/color"
	"github.com/golang/protobuf/ptypes"
	spvwallet "github.com/qshuai/blockchain-wallet"
	"github.com/qshuai/blockchain-wallet/api"
	"github.com/qshuai/blockchain-wallet/api/pb"
	"github.com/qshuai/blockchain-wallet/db"
	"github.com/qshuai/blockchain-wallet/gui"
	"github.com/qshuai/blockchain-wallet/gui/bootstrap"
	"github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
	"github.com/yawning/bulb"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
)

type Settings struct {
	FiatCode      string `json:"fiatCode"`
	FiatSymbol    string `json:"fiatSymbol"`
	FeeLevel      string `json:"feeLevel"`
	SelectBox     string `json:"selectBox"`
	BitcoinUnit   string `json:"bitcoinUnit"`
	DecimalPlaces int    `json:"decimalPlaces"`
	TrustedPeer   string `json:"trustedPeer"`
	Proxy         string `json:"proxy"`
	Fees          Fees   `json:"fees"`
}

// Load settings
type Fees struct {
	Priority uint64 `json:"priority"`
	Normal   uint64 `json:"normal"`
	Economic uint64 `json:"economic"`
	FeeAPI   string `json:"feeAPI"`
}

var wallet *spvwallet.SPVWallet

func Start(cmd *cobra.Command, args []string) {
	var err error

	// Create a new config
	config := spvwallet.NewDefaultConfig()

	dataDir, err := cmd.Flags().GetString("datadir")
	if err != nil {
		fmt.Printf("invalid datadir: %s", err)
		return
	}
	if dataDir != "" {
		config.DataDir = dataDir
	}

	testNet, err := cmd.Flags().GetBool("testnet")
	if err != nil {
		fmt.Printf("invlid boolean for testnet parameter: %s", err)
		return
	}

	regTest, err := cmd.Flags().GetBool("regtest")
	if err != nil {
		fmt.Printf("invlid boolean for regtest parameter: %s", err)
		return
	}
	if testNet && regTest {
		fmt.Println("Invalid combination of testnet and regtest modes")
		return
	}

	basePath := config.DataDir
	if testNet {
		config.Params = &chaincfg.TestNet3Params
		config.DataDir = path.Join(config.DataDir, "testnet")
	}
	if regTest {
		config.Params = &chaincfg.RegressionNetParams
		config.DataDir = path.Join(config.DataDir, "regtest")
	}

	_, err = os.Stat(config.DataDir)
	if os.IsNotExist(err) {
		err = os.Mkdir(config.DataDir, os.ModePerm)
		if err != nil {
			fmt.Printf("create datadir faield: %s", err)
			return
		}
	}

	mnemonic, err := cmd.Flags().GetString("mnemonic")
	if err != nil {
		fmt.Printf("invalid mnemonic: %s", err)
		return
	}
	if mnemonic != "" {
		config.Mnemonic = mnemonic
	}

	node, err := cmd.Flags().GetString("node")
	if err != nil {
		fmt.Printf("invalid node address： %s", err)
		return
	}

	if node != "" {
		addr, err := net.ResolveTCPAddr("tcp", node)
		if err != nil {
			fmt.Printf("invalid node address: %s", err)
			return
		}

		config.TrustedPeer = addr
	}

	tor, err := cmd.Flags().GetBool("tor")
	if err != nil {
		fmt.Printf("invalid boolean paramenter: %s", err)
		return
	}
	if tor {
		var conn *bulb.Conn
		conn, err = bulb.Dial("tcp4", "127.0.0.1:9151")
		if err != nil {
			fmt.Printf("Tor daemon not found: %s", err)
			return
		}

		dialer, err := conn.Dialer(nil)
		if err != nil {
			fmt.Printf("tor dial error: %s", err)
			return
		}
		config.Proxy = dialer
	}

	feeApi, err := cmd.Flags().GetString("fee-api")
	if err != nil {
		fmt.Printf("invalid string parameter： %s", err)
		return
	}

	if feeApi != "" {
		u, err := url.Parse(feeApi)
		if err != nil {
			fmt.Printf("invalid api link: %s", err)
			return
		}

		config.FeeAPI = *u
	}

	// Make the logging a little prettier
	config.Logger = logrus.Logger{
		Out: os.Stdout,
	}

	stdout, err := cmd.Flags().GetBool("stdout")
	if err != nil {
		fmt.Printf("invalid boolean parameter: %s", err)
		return
	}
	if stdout {
		// todo<qshuai>
	}

	// Select wallet datastore
	sqliteDatastore, _ := db.Create(config.DataDir)
	config.DB = sqliteDatastore

	mn, _ := sqliteDatastore.GetMnemonic()
	if mn != "" {
		config.Mnemonic = mn
	}
	cd, err := sqliteDatastore.GetCreationDate()
	if err == nil {
		config.CreationDate = cd
	}

	// Write version file
	f, err := os.Create(path.Join(basePath, "version"))
	if err != nil {
		fmt.Printf("create version file error: %s", err)
		return
	}

	_, err = f.Write([]byte("1"))
	if err != nil {
		fmt.Printf("write version information to file error: %s", err)
		return
	}
	err = f.Close()
	if err != nil {
		fmt.Printf("close version file error: %s", err)
		return
	}

	var settings Settings
	s, err := ioutil.ReadFile(path.Join(basePath, "settings.json"))
	if err != nil {
		settings = Settings{
			FiatCode:      "USD",
			FiatSymbol:    "$",
			FeeLevel:      "priority",
			SelectBox:     "bitcoin",
			BitcoinUnit:   "BTC",
			DecimalPlaces: 5,
			Fees: Fees{
				Priority: config.HighFee,
				Normal:   config.MediumFee,
				Economic: config.LowFee,
				FeeAPI:   config.FeeAPI.String(),
			},
		}
		f, err := os.Create(path.Join(basePath, "settings.json"))
		if err != nil {
			fmt.Printf("create settings information to file error: %s", err)
			return
		}
		s, err := json.MarshalIndent(&settings, "", "    ")
		if err != nil {
			fmt.Printf("serialize setting failed: %s", err)
			return
		}
		_, err = f.Write(s)
		if err != nil {
			fmt.Printf("write settings information to file error: %s", err)
			return
		}
		err = f.Close()
		if err != nil {
			fmt.Printf("close settings file error: %s", err)
			return
		}
	} else {
		err := json.Unmarshal([]byte(s), &settings)
		if err != nil {
			fmt.Printf("deserialize setting file error: %s", err)
			return
		}
	}
	if settings.TrustedPeer != "" {
		var tp net.Addr
		tp, err = net.ResolveTCPAddr("tcp", settings.TrustedPeer)
		if err != nil {
			fmt.Printf("invalid uri: %s", err)
			return
		}
		config.TrustedPeer = tp
	}

	if settings.Proxy != "" {
		tbProxyURL, err := url.Parse("socks5://" + settings.Proxy)
		if err != nil {
			fmt.Printf("invalid proxy setting: %s", err)
			return
		}
		tbDialer, err := proxy.FromURL(tbProxyURL, proxy.Direct)
		if err != nil {
			fmt.Printf("invalid proxy connect: %s", err)
			return
		}
		config.Proxy = tbDialer
	}
	openFeeApi, err := url.Parse(settings.Fees.FeeAPI)
	if err != nil {
		fmt.Printf("invalid fee api: %s", err)
		return
	}
	config.FeeAPI = *openFeeApi
	config.HighFee = settings.Fees.Priority
	config.MediumFee = settings.Fees.Normal
	config.LowFee = settings.Fees.Economic

	strartPoint, err := cmd.Flags().GetString("startpoint")
	if err != nil {
		fmt.Printf("inavlid string paramter: %s", err)
		return
	}
	if strartPoint != "" {
		creationDate, err := time.Parse("2006-01-02 15:04:05", strartPoint)
		if err != nil {
			fmt.Printf("Wallet creation date timestamp invalid: %s", err)
			return
		}
		config.CreationDate = creationDate
	}

	// Create the wallet
	wallet, err := spvwallet.NewSPVWallet(config)
	if err != nil {
		fmt.Printf("setup wallet failed: %s", err)
		return
	}

	if err := sqliteDatastore.SetMnemonic(config.Mnemonic); err != nil {
		fmt.Printf("set mnemonic error： %s", err)
		return
	}
	if err := sqliteDatastore.SetCreationDate(config.CreationDate); err != nil {
		fmt.Printf("set create datatime error: %s", err)
		return
	}

	go api.ServeAPI(wallet)

	// Start it!
	printSplashScreen()

	isGui, err := cmd.Flags().GetBool("gui")
	if err != nil {
		fmt.Printf("invalid boolean parameter: %s", err)
		return
	}

	if isGui {
		err = runGui(wallet, basePath, config)
		if err != nil {
			fmt.Printf("gui start failed: %s", err)
			return
		}
	} else {
		wallet.Start()
		var wg sync.WaitGroup
		wg.Add(1)
		wg.Wait()
	}
}

func runGui(wallet *spvwallet.SPVWallet, basepath string, config *spvwallet.Config) error {
	go wallet.Start()

	type Stats struct {
		Confirmed    int64  `json:"confirmed"`
		Fiat         string `json:"fiat"`
		Transactions int    `json:"transactions"`
		Height       uint32 `json:"height"`
		ExchangeRate string `json:"exchangeRate"`
	}

	txc := make(chan uint32)
	listener := func(wi.TransactionCallback) {
		h, _ := wallet.ChainTip()
		txc <- h
	}
	wallet.AddTransactionListener(listener)

	tc := make(chan struct{})
	rc := make(chan int)

	os.RemoveAll(path.Join(basepath, "resources"))
	iconPath := path.Join(basepath, "icon.png")
	_, err := os.Stat(iconPath)
	if os.IsNotExist(err) {
		f, err := os.Create(iconPath)
		if err != nil {
			return err
		}
		icon, err := gui.AppIconPngBytes()
		if err != nil {
			return err
		}
		f.Write(icon)
		defer f.Close()
	}

	// Run bootstrap
	if err := bootstrap.Run(bootstrap.Options{
		AstilectronOptions: astilectron.Options{
			AppName:            "spvwallet",
			AppIconDefaultPath: iconPath,
			//AppIconDarwinPath:  p + "/gopher.icns",
			BaseDirectoryPath: basepath,
		},
		Homepage: "index.html",
		MessageHandler: func(w *astilectron.Window, m bootstrap.MessageIn) {
			switch m.Name {
			case "getStats":
				type P struct {
					CurrencyCode string `json:"currencyCode"`
				}
				var p P
				if err := json.Unmarshal(m.Payload, &p); err != nil {
					logrus.Errorf("Unmarshaling %s failed", m.Payload)
					return
				}
				confirmed, _ := wallet.Balance()
				txs, err := wallet.Transactions()
				if err != nil {
					logrus.Errorf(err.Error())
					return
				}
				rate, err := wallet.ExchangeRates().GetExchangeRate(p.CurrencyCode)
				if err != nil {
					logrus.Errorf("Failed to get exchange rate")
					return
				}
				btcVal := float64(confirmed) / 100000000
				fiatVal := float64(btcVal) * rate
				height, _ := wallet.ChainTip()

				st := Stats{
					Confirmed:    confirmed,
					Fiat:         fmt.Sprintf("%.2f", fiatVal),
					Transactions: len(txs),
					Height:       height,
					ExchangeRate: fmt.Sprintf("%.2f", rate),
				}
				w.SendMessage(bootstrap.MessageOut{Name: "statsUpdate", Payload: st})
			case "getAddress":
				addr := wallet.CurrentAddress(wi.EXTERNAL)
				w.SendMessage(bootstrap.MessageOut{Name: "address", Payload: addr.EncodeAddress()})
			case "send":
				type P struct {
					Address  string  `json:"address"`
					Amount   float64 `json:"amount"`
					Note     string  `json:"note"`
					FeeLevel string  `json:"feeLevel"`
				}
				var p P
				if err := json.Unmarshal(m.Payload, &p); err != nil {
					logrus.Errorf("Unmarshaling %s failed", m.Payload)
					return
				}
				var feeLevel wi.FeeLevel
				switch strings.ToLower(p.FeeLevel) {
				case "priority":
					feeLevel = wi.PRIOIRTY
				case "normal":
					feeLevel = wi.NORMAL
				case "economic":
					feeLevel = wi.ECONOMIC
				default:
					feeLevel = wi.NORMAL
				}
				addr, err := btcutil.DecodeAddress(p.Address, wallet.Params())
				if err != nil {
					w.SendMessage(bootstrap.MessageOut{Name: "spendError", Payload: "Invalid address"})
					return
				}
				_, err = wallet.Spend(int64(p.Amount), addr, feeLevel, "", false)
				if err != nil {
					w.SendMessage(bootstrap.MessageOut{Name: "spendError", Payload: err.Error()})
				}
			case "clipboard":
				type P struct {
					Data string `json:"data"`
				}
				var p P
				if err := json.Unmarshal(m.Payload, &p); err != nil {
					logrus.Errorf("Unmarshaling %s failed", m.Payload)
					return
				}
				clipboard.WriteAll(p.Data)
			case "putSettings":
				var setstr string
				if err := json.Unmarshal(m.Payload, &setstr); err != nil {
					logrus.Errorf("Unmarshaling %s failed", m.Payload)
					return
				}
				var settings Settings
				if err := json.Unmarshal([]byte(setstr), &settings); err != nil {
					logrus.Errorf("Unmarshaling %s failed", m.Payload)
					return
				}

				f, err := os.Create(path.Join(basepath, "settings.json"))
				if err != nil {
					logrus.Error(err.Error())
					return
				}
				defer f.Close()
				b, err := json.MarshalIndent(&settings, "", "    ")
				if err != nil {
					logrus.Error(err.Error())
					return
				}
				f.Write(b)
			case "getSettings":
				settings, err := ioutil.ReadFile(path.Join(basepath, "settings.json"))
				if err != nil {
					logrus.Error(err.Error())
				}
				w.SendMessage(bootstrap.MessageOut{Name: "settings", Payload: string(settings)})
			case "openbrowser":
				var url string
				if err := json.Unmarshal(m.Payload, &url); err != nil {
					logrus.Errorf("Unmarshaling %s failed", m.Payload)
					return
				}
				open.Run(url)
			case "resync":
				wallet.ReSyncBlockchain(time.Time{})
			case "restore":
				var mnemonic string
				if err := json.Unmarshal(m.Payload, &mnemonic); err != nil {
					logrus.Errorf("Unmarshaling %s failed", m.Payload)
					return
				}
				wallet.Close()
				os.Remove(path.Join(config.DataDir, "wallet.db"))
				os.Remove(path.Join(config.DataDir, "headers.bin"))
				sqliteDatastore, _ := db.Create(config.DataDir)
				config.DB = sqliteDatastore
				config.Mnemonic = mnemonic
				config.CreationDate = time.Time{}
				wallet, err = spvwallet.NewSPVWallet(config)
				if err != nil {
					logrus.Errorf("Unmarshaling %s failed", m.Payload)
					return
				}
				sqliteDatastore.SetMnemonic(mnemonic)
				sqliteDatastore.SetCreationDate(time.Time{})
				go wallet.Start()
			case "minimize":
				go func() {
					w.Hide()
					tc <- struct{}{}
				}()
			case "showTransactions":
				go func() {
					rc <- 649
				}()
				txs, err := wallet.Transactions()
				if err != nil {
					w.SendMessage(bootstrap.MessageOut{Name: "txError", Payload: err.Error()})
				}
				w.SendMessage(bootstrap.MessageOut{Name: "transactions", Payload: txs})
			case "getTransactions":
				txs, err := wallet.Transactions()
				if err != nil {
					w.SendMessage(bootstrap.MessageOut{Name: "txError", Payload: err.Error()})
				}
				w.SendMessage(bootstrap.MessageOut{Name: "transactions", Payload: txs})
			case "hide":
				go func() {
					rc <- 341
				}()
			case "showSettings":
				go func() {
					rc <- 649
				}()
			case "getMnemonic":
				w.SendMessage(bootstrap.MessageOut{Name: "mnemonic", Payload: wallet.Mnemonic()})
			}
		},
		RestoreAssets: gui.RestoreAssets,
		WindowOptions: &astilectron.WindowOptions{
			Center:         astilectron.PtrBool(true),
			Height:         astilectron.PtrInt(340),
			Width:          astilectron.PtrInt(621),
			Maximizable:    astilectron.PtrBool(false),
			Fullscreenable: astilectron.PtrBool(false),
			Resizable:      astilectron.PtrBool(false),
		},
		TrayOptions: &astilectron.TrayOptions{
			Image: astilectron.PtrStr(iconPath),
		},
		TrayChan:          tc,
		ResizeChan:        rc,
		TransactionChan:   txc,
		BaseDirectoryPath: basepath,
		Wallet:            wallet,
		//Debug:             true,
	}); err != nil {
		logrus.Fatal(err)
	}

	return nil
}

func Shutdown() {
	wallet.Close()
}

func printSplashScreen() {
	blue := color.New(color.FgBlue)
	white := color.New(color.FgWhite)
	white.Printf("  _______________________   ______")
	blue.Println("      __        .__  .__          __")
	white.Printf(` /   _____/\______   \   \ /   /`)
	blue.Println(`  \    /  \_____  |  | |  |   _____/  |_`)
	white.Printf(` \_____  \  |     ___/\   Y   /`)
	blue.Println(`\   \/\/   /\__  \ |  | |  | _/ __ \   __\`)
	white.Printf(` /        \ |    |     \     / `)
	blue.Println(` \        /  / __ \|  |_|  |_\  ___/|  |`)
	white.Printf(`/_______  / |____|      \___/ `)
	blue.Println(`   \__/\  /  (____  /____/____/\___  >__|`)
	white.Printf(`	\/ `)
	blue.Println(`                           \/        \/               \/`)
	blue.DisableColor()
	white.DisableColor()
	fmt.Println("")
	fmt.Println("SPVWallet v" + spvwallet.WalletVersion + " starting...")
	fmt.Println("[Press Ctrl+C to exit]")
}

func Stop(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	_, err = client.Stop(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("call stop command to server failed: %s\n", err)
		return
	}

	fmt.Println("stopping...")
}

func Address(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
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
		fmt.Printf("call get current address command to server failed: %s\n", err)
		return
	}

	fmt.Println(resp.Addr)
}

func NewAddress(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
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
		fmt.Sprintf("call create a new address failed: %s\n", err)
		return
	}

	fmt.Println(resp.Addr)
}

func ChainTip(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.ChainTip(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("call get chain tip failed: %s\n", err)
		return
	}

	fmt.Println(resp.Height)
}

func DumpHeaders(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		client, conn, err := newGRPCClient()
		if err != nil {
			fmt.Printf("setup grpc connection failed: %s\n", err)
		}
		defer conn.Close()

		stream, err := client.DumpHeaders(context.Background(), &pb.Empty{})
		if err != nil {
			fmt.Printf("call dump header to server failed: %s\n", err)
			return
		}

		for {
			hdr, err := stream.Recv()
			if err != nil {
				fmt.Printf("receive headers from serve failed: %s\n", err)
				return
			}

			fmt.Println(hdr.Entry)
		}
	}

	headerDB, err := spvwallet.NewHeaderDB(args[0])
	if err != nil {
		fmt.Printf("create a new header database failed: %s\n", err)
	} else {
		headerDB.Print(os.Stdout)
	}
}

func Balance(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.Balance(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("call get balance command to server failed: %s\n", err)
		return
	}

	type ret struct {
		Confirmed   uint64 `json:"confirmed"`
		Unconfirmed uint64 `json:"unconfirmed"`
	}
	out, err := json.MarshalIndent(&ret{resp.Confirmed, resp.Unconfirmed}, "", "    ")
	if err != nil {
		fmt.Printf("serialize balance information failed: %s\n", err)
		return
	}

	fmt.Println(string(out))
}

func MasterPrivateKey(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.MasterPrivateKey(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("get master private key failed: %s\n", err)
		return
	}

	fmt.Println(resp.Key)
}

func MasterPublicKey(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.MasterPublicKey(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("get master public key failed: %s\n", err)
	}

	fmt.Println(resp.Key)
}

func DumpPrivateKey(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Println("An address required")
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.GetKey(context.Background(), &pb.Address{args[0]})
	if err != nil {
		fmt.Printf("dump the private key for the address failed: %s\n", err)
		return
	}

	fmt.Println(resp.Key)
}

func ListAddresses(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.ListAddresses(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("list all address in wallet failed: %s\n", err)
		return
	}

	for _, addr := range resp.Addresses {
		fmt.Println(addr.Addr)
	}
}

func ListPrivateKey(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.ListKeys(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("list all private key in wallet failed: %s", err)
	}

	for _, key := range resp.Keys {
		fmt.Println(key.Key)
	}
}

func HasKey(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Printf("The address required")
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.HasKey(context.Background(), &pb.Address{args[0]})
	if err != nil {
		fmt.Printf("call has key command to server failed: %s", err)
	}

	fmt.Println(resp.Bool)
}

func ListTransaction(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.Transactions(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("call list transaction command to server failed: %s", err)
		return
	}

	chainTip, err := client.ChainTip(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("call chain tip command to server failed: %s", err)
		return
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
	txns := make([]Tx, 0, len(resp.Transactions))
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
		fmt.Printf("serilize transaction list failed: %s", err)
		return
	}

	fmt.Println(string(formatted))
}

func GetTransaction(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Printf("transaction hash required")
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.GetTransaction(context.Background(), &pb.Txid{args[0]})
	if err != nil {
		fmt.Printf("call get transaction command to server failed: %s", err)
		return
	}

	chainTip, err := client.ChainTip(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("get chain tip failed: %s", err)
		return
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
		fmt.Printf("serialise transaction failed: %s", err)
		return
	}

	fmt.Println(string(formatted))
}

func GetFeePerByte(command *cobra.Command, args []string) {
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

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.GetFeePerByte(context.Background(), &pb.FeeLevelSelection{feeLevel})
	if err != nil {
		fmt.Printf("call get fee per byte failed: %s", err)
		return
	}

	fmt.Println(resp.Fee)
}

func Spend(command *cobra.Command, args []string) {
	if len(args) < 2 {
		fmt.Println("the receiving address and amount required")
		return
	}

	var feeLevel pb.FeeLevel
	userSelection := ""
	if len(args) > 2 {
		userSelection = args[2]
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
		fmt.Printf("invalid amount: %s", err)
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.Spend(context.Background(), &pb.SpendInfo{args[0], uint64(amt), feeLevel})
	if err != nil {
		fmt.Printf("call spend command to server failed: %s", err)
		return
	}

	fmt.Println(resp.Hash)
}

func BumpFee(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Println("transaction hash required")
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.BumpFee(context.Background(), &pb.Txid{args[0]})
	if err != nil {
		fmt.Printf("get fee for transction failed: %s", err)
		return
	}

	fmt.Println(resp.Hash)
}

func Peers(command *cobra.Command, args []string) {
	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.Peers(context.Background(), &pb.Empty{})
	if err != nil {
		fmt.Printf("get peers information failed: %s", err)
		return
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
	if err != nil {
		fmt.Printf("serialize peers list failed: %s", err)
		return
	}

	fmt.Println(string(out))
}

func WatchScript(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Println("Address or script required")
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	_, err = client.AddWatchedAddress(context.Background(), &pb.Address{args[0]})
	if err != nil {
		fmt.Printf("watch address failed: %s", err)
		return
	}

	fmt.Println(true)
}

func GetConfirmations(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Println("Txid is required")
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.GetConfirmations(context.Background(), &pb.Txid{args[0]})
	if err != nil {
		fmt.Printf("get confirmation of tansaction failed: %s", err)
		return
	}

	fmt.Println(resp.Confirmations)
}

func SweepAddress(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Println("Sweep data is required")
		return
	}

	sweepInfo := new(pb.SweepInfo)
	if err := jsonpb.UnmarshalString(args[0], sweepInfo); err != nil {
		fmt.Printf("deseriaze failed: %s", err)
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	resp, err := client.SweepAddress(context.Background(), sweepInfo)
	if err != nil {
		fmt.Printf("swpep address failed: %s", err)
		return
	}

	fmt.Println(resp.Hash)
}

func ReSyncBlockchain(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Println("transaction hash required")
		return
	}

	t, err := time.Parse("2006-01-02 15:04:05", args[0])
	if err != nil {
		fmt.Printf("malformat datetime: %s", err)
		return
	}

	ts, err := ptypes.TimestampProto(t)
	if err != nil {
		fmt.Printf("invalid timestamp: %s", err)
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	_, err = client.ReSyncBlockchain(context.Background(), ts)
	if err != nil {
		fmt.Printf("resync blockchain failed: %s", err)
		return
	}

	fmt.Println("resync...")
}

func CreateMultisigSignature(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Println("Multisig data is required")
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	multsigInfo := new(pb.CreateMultisigInfo)
	if err := jsonpb.UnmarshalString(args[0], multsigInfo); err != nil {
		fmt.Printf("deserialize error: %s", err)
		return
	}
	resp, err := client.CreateMultisigSignature(context.Background(), multsigInfo)
	if err != nil {
		fmt.Printf("create multisig signature failed: %s", err)
		return
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
	if err != nil {
		fmt.Printf("serialize failed: %s", err)
		return
	}

	fmt.Println(string(out))
}

func MultiSign(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Println("Multisig data is required")
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	multsignInfo := new(pb.MultisignInfo)
	if err := jsonpb.UnmarshalString(args[0], multsignInfo); err != nil {
		fmt.Printf("deserialize error: %s", err)
		return
	}
	resp, err := client.Multisign(context.Background(), multsignInfo)
	if err != nil {
		fmt.Printf("multi sign failed: %s", err)
		return
	}

	if multsignInfo.Broadcast {
		r := bytes.NewReader(resp.Tx)
		msgTx := wire.NewMsgTx(1)
		err = msgTx.BtcDecode(r, 1, wire.WitnessEncoding)
		if err != nil {
			fmt.Printf("decode transaction failed: %s", err)
			return
		}

		fmt.Println(msgTx.TxHash().String())
		return
	}

	fmt.Println(hex.EncodeToString(resp.Tx))
}

func EstimateFee(command *cobra.Command, args []string) {
	if len(args) <= 0 {
		fmt.Println("Tx data is required")
		return
	}

	client, conn, err := newGRPCClient()
	if err != nil {
		fmt.Printf("setup grpc connection failed: %s\n", err)
		return
	}
	defer conn.Close()

	estimateFeeData := new(pb.EstimateFeeData)
	if err := jsonpb.UnmarshalString(args[0], estimateFeeData); err != nil {
		fmt.Printf("deserialize error: %s", err)
		return
	}
	resp, err := client.EstimateFee(context.Background(), estimateFeeData)
	if err != nil {
		fmt.Printf("estimate transaction fee failed: %s", err)
		return
	}

	fmt.Println(resp.Fee)
}

func newGRPCClient() (pb.APIClient, *grpc.ClientConn, error) {
	// Set up a connection to the server.
	conn, err := grpc.Dial(api.Addr, grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}

	return pb.NewAPIClient(conn), conn, nil
}
