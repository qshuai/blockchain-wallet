package spvwallet

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/qshuai/blockchain-wallet/exchangerates"
	log "github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip39"
)

type SPVWallet struct {
	params *chaincfg.Params

	masterPrivateKey *hdkeychain.ExtendedKey
	masterPublicKey  *hdkeychain.ExtendedKey

	mnemonic string

	feeProvider *FeeProvider

	repoPath string

	blockchain  *Blockchain
	txstore     *TxStore
	peerManager *PeerManager
	keyManager  *KeyManager
	wireService *WireService

	fPositives    chan *peer.Peer
	fpAccumulator map[int32]int32
	mutex         *sync.RWMutex

	creationDate time.Time

	running bool

	config *PeerManagerConfig

	exchangeRates wallet.ExchangeRates
}

var _ = wallet.Wallet(&SPVWallet{})

const WalletVersion = "0.1.0"

func NewSPVWallet(config *Config) (*SPVWallet, error) {

	if config.Mnemonic == "" {
		ent, err := bip39.NewEntropy(128)
		if err != nil {
			return nil, err
		}
		mnemonic, err := bip39.NewMnemonic(ent)
		if err != nil {
			return nil, err
		}
		config.Mnemonic = mnemonic
		config.CreationDate = time.Now()
	}
	seed := bip39.NewSeed(config.Mnemonic, "")

	mPrivKey, err := hdkeychain.NewMaster(seed, config.Params)
	if err != nil {
		return nil, err
	}
	mPubKey, err := mPrivKey.Neuter()
	if err != nil {
		return nil, err
	}
	w := &SPVWallet{
		repoPath:         config.DataDir,
		masterPrivateKey: mPrivKey,
		masterPublicKey:  mPubKey,
		mnemonic:         config.Mnemonic,
		params:           config.Params,
		creationDate:     config.CreationDate,
		feeProvider: NewFeeProvider(
			config.MaxFee,
			config.HighFee,
			config.MediumFee,
			config.LowFee,
			config.FeeAPI.String(),
			config.Proxy,
		),
		fPositives:    make(chan *peer.Peer),
		fpAccumulator: make(map[int32]int32),
		mutex:         new(sync.RWMutex),
	}

	bpf := exchangerates.NewBitcoinPriceFetcher(config.Proxy)
	w.exchangeRates = bpf
	if !config.DisableExchangeRates {
		go bpf.Run()
	}

	w.keyManager, err = NewKeyManager(config.DB.Keys(), w.params, w.masterPrivateKey)

	w.txstore, err = NewTxStore(w.params, config.DB, w.keyManager)
	if err != nil {
		return nil, err
	}

	w.blockchain, err = NewBlockchain(w.repoPath, w.creationDate, w.params)
	if err != nil {
		return nil, err
	}
	minSync := 5
	if config.TrustedPeer != nil {
		minSync = 1
	}
	wireConfig := &WireServiceConfig{
		txStore:            w.txstore,
		chain:              w.blockchain,
		walletCreationDate: w.creationDate,
		minPeersForSync:    minSync,
		params:             w.params,
	}

	ws := NewWireService(wireConfig)
	w.wireService = ws

	getNewestBlock := func() (*chainhash.Hash, int32, error) {
		sh, err := w.blockchain.BestBlock()
		if err != nil {
			return nil, 0, err
		}
		h := sh.header.BlockHash()
		return &h, int32(sh.height), nil
	}

	w.config = &PeerManagerConfig{
		UserAgentName:    config.UserAgent,
		UserAgentVersion: WalletVersion,
		Params:           w.params,
		AddressCacheDir:  config.DataDir,
		Proxy:            config.Proxy,
		GetNewestBlock:   getNewestBlock,
		MsgChan:          ws.MsgChan(),
	}

	if config.TrustedPeer != nil {
		w.config.TrustedPeer = config.TrustedPeer
	}

	w.peerManager, err = NewPeerManager(w.config)
	if err != nil {
		return nil, err
	}

	return w, nil
}

func (w *SPVWallet) Start() {
	w.running = true
	go w.wireService.Start()
	go w.peerManager.Start()
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// API
//
//////////////

func (w *SPVWallet) CurrencyCode() string {
	if w.params.Name == chaincfg.MainNetParams.Name {
		return "btc"
	} else {
		return "tbtc"
	}
}

func (w *SPVWallet) IsDust(amount int64) bool {
	return txrules.IsDustAmount(btcutil.Amount(amount), 25, txrules.DefaultRelayFeePerKb)
}

func (w *SPVWallet) MasterPrivateKey() *hdkeychain.ExtendedKey {
	return w.masterPrivateKey
}

func (w *SPVWallet) MasterPublicKey() *hdkeychain.ExtendedKey {
	return w.masterPublicKey
}

func (w *SPVWallet) ChildKey(keyBytes []byte, chaincode []byte, isPrivateKey bool) (*hdkeychain.ExtendedKey, error) {
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	var id []byte
	if isPrivateKey {
		id = w.params.HDPrivateKeyID[:]
	} else {
		id = w.params.HDPublicKeyID[:]
	}
	hdKey := hdkeychain.NewExtendedKey(
		id,
		keyBytes,
		chaincode,
		parentFP,
		0,
		0,
		isPrivateKey)
	return hdKey.Child(0)
}

func (w *SPVWallet) Mnemonic() string {
	return w.mnemonic
}

func (w *SPVWallet) ConnectedPeers() []*peer.Peer {
	return w.peerManager.ConnectedPeers()
}

func (w *SPVWallet) CurrentAddress(purpose wallet.KeyPurpose) btcutil.Address {
	key, _ := w.keyManager.GetCurrentKey(purpose)
	addr, _ := key.Address(w.params)
	return btcutil.Address(addr)
}

func (w *SPVWallet) NewAddress(purpose wallet.KeyPurpose) btcutil.Address {
	i, _ := w.txstore.Keys().GetUnused(purpose)
	key, _ := w.keyManager.generateChildKey(purpose, uint32(i[1]))
	addr, _ := key.Address(w.params)
	w.txstore.Keys().MarkKeyAsUsed(addr.ScriptAddress())
	w.txstore.PopulateAdrs()
	return btcutil.Address(addr)
}

func (w *SPVWallet) DecodeAddress(addr string) (btcutil.Address, error) {
	return btcutil.DecodeAddress(addr, w.params)
}

func (w *SPVWallet) ScriptToAddress(script []byte) (btcutil.Address, error) {
	return scriptToAddress(script, w.params)
}

func scriptToAddress(script []byte, params *chaincfg.Params) (btcutil.Address, error) {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(script, params)
	if err != nil {
		return &btcutil.AddressPubKeyHash{}, err
	}
	if len(addrs) == 0 {
		return &btcutil.AddressPubKeyHash{}, errors.New("unknown script")
	}
	return addrs[0], nil
}

func (w *SPVWallet) AddressToScript(addr btcutil.Address) ([]byte, error) {
	return txscript.PayToAddrScript(addr)
}

func (w *SPVWallet) HasKey(addr btcutil.Address) bool {
	_, err := w.keyManager.GetKeyForScript(addr.ScriptAddress())
	if err != nil {
		return false
	}
	return true
}

func (w *SPVWallet) GetKey(addr btcutil.Address) (*btcec.PrivateKey, error) {
	key, err := w.keyManager.GetKeyForScript(addr.ScriptAddress())
	if err != nil {
		return nil, err
	}
	return key.ECPrivKey()
}

func (w *SPVWallet) ListAddresses() []btcutil.Address {
	keys := w.keyManager.GetKeys()
	addrs := []btcutil.Address{}
	for _, k := range keys {
		addr, err := k.Address(w.params)
		if err != nil {
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

func (w *SPVWallet) ListKeys() []btcec.PrivateKey {
	keys := w.keyManager.GetKeys()
	list := []btcec.PrivateKey{}
	for _, k := range keys {
		priv, err := k.ECPrivKey()
		if err != nil {
			continue
		}
		list = append(list, *priv)
	}
	return list
}

func (w *SPVWallet) Balance() (confirmed, unconfirmed int64) {
	utxos, _ := w.txstore.Utxos().GetAll()
	stxos, _ := w.txstore.Stxos().GetAll()
	for _, utxo := range utxos {
		if !utxo.WatchOnly {
			if utxo.AtHeight > 0 {
				confirmed += utxo.Value
			} else {
				if w.checkIfStxoIsConfirmed(utxo, stxos) {
					confirmed += utxo.Value
				} else {
					unconfirmed += utxo.Value
				}
			}
		}
	}
	return confirmed, unconfirmed
}

func (w *SPVWallet) Transactions() ([]wallet.Txn, error) {
	height, _ := w.ChainTip()
	txns, err := w.txstore.Txns().GetAll(false)
	if err != nil {
		return txns, err
	}
	for i, tx := range txns {
		var confirmations int32
		var status wallet.StatusCode
		confs := int32(height) - tx.Height + 1
		if tx.Height <= 0 {
			confs = tx.Height
		}
		switch {
		case confs < 0:
			status = wallet.StatusDead
		case confs == 0 && time.Since(tx.Timestamp) <= time.Hour*6:
			status = wallet.StatusUnconfirmed
		case confs == 0 && time.Since(tx.Timestamp) > time.Hour*6:
			status = wallet.StatusDead
		case confs > 0 && confs < 6:
			status = wallet.StatusPending
			confirmations = confs
		case confs > 5:
			status = wallet.StatusConfirmed
			confirmations = confs
		}
		tx.Confirmations = int64(confirmations)
		tx.Status = status
		txns[i] = tx
	}
	return txns, nil
}

func (w *SPVWallet) GetTransaction(txid chainhash.Hash) (wallet.Txn, error) {
	txn, err := w.txstore.Txns().Get(txid)
	if err == nil {
		tx := wire.NewMsgTx(1)
		rbuf := bytes.NewReader(txn.Bytes)
		err := tx.BtcDecode(rbuf, wire.ProtocolVersion, wire.WitnessEncoding)
		if err != nil {
			return txn, err
		}
		outs := []wallet.TransactionOutput{}
		for i, out := range tx.TxOut {
			var addr btcutil.Address
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, w.params)
			if err != nil {
				log.Warningf("error extracting address from txn pkscript: %v\n", err)
			}
			if len(addrs) == 0 {
				addr = nil
			} else {
				addr = addrs[0]
			}
			tout := wallet.TransactionOutput{
				Address: addr,
				Value:   out.Value,
				Index:   uint32(i),
			}
			outs = append(outs, tout)
		}
		txn.Outputs = outs
	}
	return txn, err
}

func (w *SPVWallet) GetConfirmations(txid chainhash.Hash) (uint32, uint32, error) {
	txn, err := w.txstore.Txns().Get(txid)
	if err != nil {
		return 0, 0, err
	}
	if txn.Height == 0 {
		return 0, 0, nil
	}
	chainTip, _ := w.ChainTip()
	return chainTip - uint32(txn.Height) + 1, uint32(txn.Height), nil
}

func (w *SPVWallet) checkIfStxoIsConfirmed(utxo wallet.Utxo, stxos []wallet.Stxo) bool {
	for _, stxo := range stxos {
		if !stxo.Utxo.WatchOnly {
			if stxo.SpendTxid.IsEqual(&utxo.Op.Hash) {
				if stxo.SpendHeight > 0 {
					return true
				} else {
					return w.checkIfStxoIsConfirmed(stxo.Utxo, stxos)
				}
			} else if stxo.Utxo.IsEqual(&utxo) {
				if stxo.Utxo.AtHeight > 0 {
					return true
				} else {
					return false
				}
			}
		}
	}
	return false
}

func (w *SPVWallet) Params() *chaincfg.Params {
	return w.params
}

func (w *SPVWallet) AddTransactionListener(callback func(wallet.TransactionCallback)) {
	w.txstore.listeners = append(w.txstore.listeners, callback)
}

func (w *SPVWallet) ChainTip() (uint32, chainhash.Hash) {
	var ch chainhash.Hash
	sh, err := w.blockchain.db.GetBestHeader()
	if err != nil {
		return 0, ch
	}
	return sh.height, sh.header.BlockHash()
}

func (w *SPVWallet) AddWatchedAddresses(addrs ...btcutil.Address) error {

	var err error
	var watchedScripts [][]byte

	for _, addr := range addrs {
		script, err := w.AddressToScript(addr)
		if err != nil {
			return err
		}
		watchedScripts = append(watchedScripts, script)
	}

	err = w.txstore.WatchedScripts().PutAll(watchedScripts)
	w.txstore.PopulateAdrs()

	w.wireService.MsgChan() <- updateFiltersMsg{}

	return err
}

func (w *SPVWallet) DumpHeaders(writer io.Writer) {
	w.blockchain.db.Print(writer)
}

func (w *SPVWallet) Close() {
	if w.running {
		log.Info("Disconnecting from peers and shutting down")
		w.peerManager.Stop()
		w.blockchain.Close()
		w.wireService.Stop()
		w.running = false
	}
}

func (w *SPVWallet) ReSyncBlockchain(fromDate time.Time) {
	w.blockchain.Rollback(fromDate)
	w.txstore.PopulateAdrs()
	w.wireService.Resync()
}

func (w *SPVWallet) ExchangeRates() wallet.ExchangeRates {
	return w.exchangeRates
}

// AssociateTransactionWithOrder used for ORDER_PAYMENT message
func (w *SPVWallet) AssociateTransactionWithOrder(cb wallet.TransactionCallback) {
	for _, l := range w.txstore.listeners {
		go l(cb)
	}
}
