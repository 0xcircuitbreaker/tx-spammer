package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	random "math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
	accounts "github.com/dominant-strategies/quai-accounts"
	"github.com/dominant-strategies/quai-accounts/keystore"
	"github.com/dominant-strategies/tx-spammer/util"
	"github.com/holiman/uint256"
)

var (
	BASEFEE   = big.NewInt(1 * params.GWei)
	MINERTIP  = big.NewInt(1 * params.GWei)
	GAS       = uint64(21000)
	VALUE     = big.NewInt(1111111111111111)
	PARAMS    = params.OrchardChainConfig
	numChains = 13
	chainList = []string{"prime", "cyprus", "cyprus1", "cyprus2", "cyprus3", "paxos", "paxos1", "paxos2", "paxos3", "hydra", "hydra1", "hydra2", "hydra3"}
	from_zone = 0
	exit      = make(chan bool)
)

func TestGenerateAddresses(t *testing.T) {
	ks := keystore.NewKeyStore(filepath.Join(os.Getenv("HOME"), ".test", "keys"), keystore.StandardScryptN, keystore.StandardScryptP)
	if len(ks.Accounts()) > 0 {
		fmt.Println("Already have keys, please delete the .test directory if you want to generate new keys")
		return
	}

	foundAddrs := 0
	common.NodeLocation = []byte{0, 0}
	fmt.Println("cyprus1")
	addrs := make([]common.Address, 0)

	for i := 0; i < 10000; i++ {
		privKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		addr := crypto.PubkeyToAddress(privKey.PublicKey)
		if common.IsInChainScope(addr.Bytes()) {
			fmt.Println(addr.Hex())
			fmt.Println(crypto.FromECDSA(privKey))
			ks.ImportECDSA(privKey, "")
			addrs = append(addrs, addr)
			foundAddrs++
		}
		if foundAddrs == 1 {
			foundAddrs = 0
			switch common.NodeLocation.Name() {
			case "cyprus1":
				common.NodeLocation = []byte{0, 1}
				fmt.Println(common.NodeLocation.Name())
			case "cyprus2":
				common.NodeLocation = []byte{0, 2}
				fmt.Println(common.NodeLocation.Name())
			case "cyprus3":
				common.NodeLocation = []byte{1, 0}
				fmt.Println(common.NodeLocation.Name())
			case "paxos1":
				common.NodeLocation = []byte{1, 1}
				fmt.Println(common.NodeLocation.Name())
			case "paxos2":
				common.NodeLocation = []byte{1, 2}
				fmt.Println(common.NodeLocation.Name())
			case "paxos3":
				common.NodeLocation = []byte{2, 0}
				fmt.Println(common.NodeLocation.Name())
			case "hydra1":
				common.NodeLocation = []byte{2, 1}
				fmt.Println(common.NodeLocation.Name())
			case "hydra2":
				common.NodeLocation = []byte{2, 2}
				fmt.Println(common.NodeLocation.Name())
			case "hydra3":
				i = 10000
			}
		}
	}
	fmt.Println("ZONE_0_0_COINBASE=" + addrs[0].String())
	fmt.Println("ZONE_0_1_COINBASE=" + addrs[1].String())
	fmt.Println("ZONE_0_2_COINBASE=" + addrs[2].String())
	fmt.Println("ZONE_1_0_COINBASE=" + addrs[3].String())
	fmt.Println("ZONE_1_1_COINBASE=" + addrs[4].String())
	fmt.Println("ZONE_1_2_COINBASE=" + addrs[5].String())
	fmt.Println("ZONE_2_0_COINBASE=" + addrs[6].String())
	fmt.Println("ZONE_2_1_COINBASE=" + addrs[7].String())
	fmt.Println("ZONE_2_2_COINBASE=" + addrs[8].String())

}

type AddressCache struct {
	addresses [][]chan common.Address
	addrLock  sync.RWMutex
}

func TestSpamTxs(t *testing.T) {
	addrCache := &AddressCache{
		addresses: make([][]chan common.Address, 3),
	}
	for i := range addrCache.addresses {
		addrCache.addresses[i] = make([]chan common.Address, 3)
		for x := range addrCache.addresses[i] {
			addrCache.addresses[i][x] = make(chan common.Address, 1000000)
		}
	}
	go GenerateAddresses(addrCache)
	config, err := util.LoadConfig(".")
	if err != nil {
		fmt.Println("cannot load config: " + err.Error())
		return
	}
	allClients := getNodeClients(config)
	ks := keystore.NewKeyStore(filepath.Join(os.Getenv("HOME"), ".test", "keys"), keystore.StandardScryptN, keystore.StandardScryptP)
	pass := ""
	for i := 0; i < 9; i++ {
		ks.Unlock(ks.Accounts()[i], pass)
		addAccToClient(&allClients, ks.Accounts()[i], i)
	}
	region := -1
	for i := 0; i < 9; i++ {
		from_zone = i % 3
		if i%3 == 0 {
			region++
		}
		addrCache.addresses = append(addrCache.addresses, make([]chan common.Address, 0, 0))
		go func(from_zone int, region int, addrCache *AddressCache) {
			if !allClients.zonesAvailable[region][from_zone] {
				return
			}
			client := allClients.zoneClients[region][from_zone]
			from := allClients.zoneAccounts[region][from_zone]
			//common.NodeLocation = *from.Address.Location() // Assuming we are in the same location as the provided key
			var toAddr common.Address
			nonce, err := client.NonceAt(context.Background(), from.Address, nil)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			nonceCounter := 0
			start1 := time.Now()
			start2 := time.Now()
			for x := 0; x < 10000000; x++ {

				var tx *types.Transaction
				if x%1000 == 0 && x != 0 {
					nonce, err = client.PendingNonceAt(context.Background(), from.Address)
					if err != nil {
						fmt.Println(err.Error())
						return
					}
					nonceCounter = 0
					fmt.Println("Time elapsed for 1000 txs in ms: ", time.Since(start2).Milliseconds())
					start2 = time.Now()
				}
				if x%5 == 0 { // Change to true for all ETXs
					toAddr = ChooseRandomETXAddress(addrCache, region, from_zone)
					// Change the params
					inner_tx := types.InternalToExternalTx{ChainID: PARAMS.ChainID, Nonce: nonce + uint64(nonceCounter), GasTipCap: MINERTIP, GasFeeCap: BASEFEE, ETXGasPrice: big.NewInt(2 * params.GWei), ETXGasLimit: 21000, ETXGasTip: big.NewInt(2 * params.GWei), Gas: GAS * 2, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
					tx = types.NewTx(&inner_tx)
				} else {
					// Change the params
					toAddr = <-addrCache.addresses[region][from_zone]
					inner_tx := types.InternalTx{ChainID: PARAMS.ChainID, Nonce: nonce + uint64(nonceCounter), GasTipCap: MINERTIP, GasFeeCap: BASEFEE, Gas: GAS, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
					tx = types.NewTx(&inner_tx)
				}
				tx, err = ks.SignTx(from, tx, PARAMS.ChainID)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				err = client.SendTransaction(context.Background(), tx)
				if err != nil {
					fmt.Println(err.Error())
				} else {
					fmt.Println(tx.Hash().String())
				}
				//time.Sleep(5 * time.Second)
				nonceCounter++
			}
			elapsed := time.Since(start1)
			fmt.Println("Time elapsed for all txs in ms: ", elapsed.Milliseconds())
		}(from_zone, region, addrCache)
	}
	<-exit
}

func ChooseRandomETXAddress(addrCache *AddressCache, region, zone int) common.Address {
	r, z := random.Intn(3), random.Intn(3)
	if r == region {
		return ChooseRandomETXAddress(addrCache, region, zone)
	} else if z == zone {
		return ChooseRandomETXAddress(addrCache, region, zone)
	}
	toAddr := <-addrCache.addresses[r][z]
	return toAddr
}

func TestOneTransaction(t *testing.T) {

	config, err := util.LoadConfig(".")
	if err != nil {
		t.Error("cannot load config: " + err.Error())
		t.Fail()
	}
	allClients := getNodeClients(config)
	client := allClients.zoneClients[0][0]

	key, err := crypto.HexToECDSA("private key")
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	signer := types.LatestSigner(PARAMS)
	toAddr := from // change for ETX
	etx := false   // change for ETX

	nonce, err := client.NonceAt(context.Background(), from, nil)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	var tx *types.Transaction

	if etx {
		inner_tx := types.InternalToExternalTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: BASEFEE, ETXGasPrice: big.NewInt(2 * params.GWei), ETXGasLimit: 21000, ETXGasTip: big.NewInt(2 * params.GWei), Gas: GAS * 2, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
		tx = types.NewTx(&inner_tx)
	} else {
		inner_tx := types.InternalTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: BASEFEE, Gas: GAS, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
		tx = types.NewTx(&inner_tx)
	}

	t.Log(tx.Hash().String())
	tx, err = types.SignTx(tx, signer, key)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}

}

func TestOpETX(t *testing.T) {
	config, err := util.LoadConfig(".")
	if err != nil {
		t.Error("cannot load config: " + err.Error())
		t.Fail()
	}
	allClients := getNodeClients(config)

	//contract, err := hex.DecodeString("60806040526040516101e03803806101e0833981810160405281019061002591906100dc565b600080600080600086888a8c8e6000f6905050505050505050610169565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061007382610048565b9050919050565b61008381610068565b811461008e57600080fd5b50565b6000815190506100a08161007a565b92915050565b6000819050919050565b6100b9816100a6565b81146100c457600080fd5b50565b6000815190506100d6816100b0565b92915050565b60008060008060008060c087890312156100f9576100f8610043565b5b600061010789828a01610091565b965050602061011889828a016100c7565b955050604061012989828a016100c7565b945050606061013a89828a016100c7565b935050608061014b89828a016100c7565b92505060a061015c89828a016100c7565b9150509295509295509295565b6069806101776000396000f3fe6080604052600080fdfea2646970667358221220ae701927ce1c6a30dbd24ad1b79952d125849aa7fd08aaa826c17c489699f20764736f6c63782c302e382e31382d646576656c6f702e323032322e31312e382b636f6d6d69742e36306161353861362e6d6f64005d")
	contract, err := hex.DecodeString("608060405260658060116000396000f3fe608060405200fea2646970667358221220c2120fc446b07160cfbb4fad9dd4938a90af53907492e05faefb40598a488d2464736f6c63782b302e382e32302d646576656c6f702e323032332e342e362b636f6d6d69742e30626564303536382e6d6f64005c")
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}

	ks := keystore.NewKeyStore(filepath.Join(os.Getenv("HOME"), ".faucet", "keys"), keystore.StandardScryptN, keystore.StandardScryptP)
	pass := ""

	for i := 0; i < 3; i++ {
		blob, err := ioutil.ReadFile("keystore/" + chainList[i] + ".json") // put keystore folder in the current directory
		if err != nil {
			t.Error("Failed to read account key contents", "file", chainList[i]+".json", "err", err)
			t.Fail()
		}
		acc, err := ks.Import(blob, pass, pass)
		if err != nil && err != keystore.ErrAccountAlreadyExists {
			t.Error("Failed to import faucet signer account", "err", err)
			t.Fail()
		}
		if err := ks.Unlock(acc, pass); err != nil {
			t.Error("Failed to unlock faucet signer account", "err", err)
			t.Fail()
		}
		addAccToClient(&allClients, acc, i)
	}
	add := byte(10)
	for x := 0; x < 1; x++ {
		if !allClients.zonesAvailable[from_zone][0] {
			continue
		}
		client := allClients.zoneClients[from_zone][0]
		from := allClients.zoneAccounts[from_zone][0]
		common.NodeLocation = *from.Address.Location() // Assuming we are in the same location as the provided key

		temp_ := from.Address.Bytes() //allClients.zoneAccounts[from_zone+1][0].Address.Bytes()
		temp_[len(temp_)-1] += add    // Tweak the recipient
		toAddr := common.BytesToAddress(temp_)
		t.Log(from.Address.String())
		t.Log(toAddr.String())
		to, err := uint256.FromHex(toAddr.Hex())
		if err != nil {
			t.Error(err.Error())
			t.Fail()
		}
		/*amount, _ := uint256.FromBig(VALUE)
		limit := uint256.NewInt(GAS)
		tip, _ := uint256.FromBig(MINERTIP)
		baseFee, _ := uint256.FromBig(BASEFEE.Mul(BASEFEE, common.Big2))*/
		data := make([]byte, 0, 0)
		temp := to.Bytes32()
		/*data = append(data, temp[:]...)
		temp = amount.Bytes32()
		data = append(data, temp[:]...)
		temp = limit.Bytes32()
		data = append(data, temp[:]...)
		temp = tip.Bytes32()
		data = append(data, temp[:]...)
		temp = baseFee.Bytes32()
		data = append(data, temp[:]...)*/
		contract = append(contract, data...)

		nonce, err := client.NonceAt(context.Background(), from.Address, nil)
		if err != nil {
			t.Error(err.Error())
			t.Fail()
		}
		balance, err := client.BalanceAt(context.Background(), from.Address, nil)
		if err != nil {
			t.Error(err.Error())
			t.Fail()
		}
		t.Log(balance.String())
		newBalance := balance.Sub(balance, big.NewInt(1e17))
		t.Log(newBalance.String())
		i := uint8(0)
		temp = uint256.NewInt(uint64(i)).Bytes32()
		contract = append(contract, temp[:]...)
		for {
			contract[len(contract)-1] = i // one byte (8 bits) for contract nonce is sufficient
			contractAddr := crypto.CreateAddress(from.Address, nonce, contract)
			if common.IsInChainScope(contractAddr.Bytes()) {
				break
			}
			i++
		}
		accessList := types.AccessList{}
		//tmpVal := big.NewInt(0) //.Add(VALUE, big.NewInt(1e18))
		inner_tx := types.InternalTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: BASEFEE, Gas: GAS, To: &toAddr, Value: newBalance, Data: nil, AccessList: accessList}
		//inner_tx := types.InternalTx{ChainID: PARAMS.ChainID, Nonce: nonce + uint64(1), GasTipCap: MINERTIP, GasFeeCap: BASEFEE, Gas: GAS, To: nil, Value: newBalance, Data: contract, AccessList: accessList}
		t.Log(types.NewTx(&inner_tx).Hash().String())
		tx, err := ks.SignTx(from, types.NewTx(&inner_tx), PARAMS.ChainID)
		if err != nil {
			t.Error(err.Error())
			t.Fail()
		}
		t.Log(tx.Hash().String())
		err = client.SendTransaction(context.Background(), tx)
		if err != nil {
			t.Error(err.Error())
			t.Fail()
		}
		add++
	}

}

func GenerateAddresses(addrCache *AddressCache) {
	for i := 0; i < 100000000; i++ {
		privKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		addr := crypto.PubkeyToAddress(privKey.PublicKey)
		location := Location(addr)
		if location == nil {
			continue
		}
		if location.HasZone() {
			addrCache.addresses[location.Region()][location.Zone()] <- addr
		}
	}
}

func TestHash(t *testing.T) {
	contract, err := hex.DecodeString("1234")
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	t.Log(hex.EncodeToString(contract))
	t.Log(crypto.Keccak256Hash([]byte("608060405234801561001057600080fd5b5060405161072c38038061072c8339818101604052810190610032919061015a565b806000908051906020019061004892919061004f565b50506102bf565b82805461005b9061022f565b90600052602060002090601f01602090048101928261007d57600085556100c4565b82601f1061009657805160ff19168380011785556100c4565b828001600101855582156100c4579182015b828111156100c35782518255916020019190600101906100a8565b5b5090506100d191906100d5565b5090565b5b808211156100ee5760008160009055506001016100d6565b5090565b6000610105610100846101cc565b61019b565b90508281526020810184848401111561011d57600080fd5b6101288482856101fc565b509392505050565b600082601f83011261014157600080fd5b81516101518482602086016100f2565b91505092915050565b60006020828403121561016c57600080fd5b600082015167ffffffffffffffff81111561018657600080fd5b61019284828501610130565b91505092915050565b6000604051905081810181811067ffffffffffffffff821117156101c2576101c1610290565b5b8060405250919050565b600067ffffffffffffffff8211156101e7576101e6610290565b5b601f19601f8301169050602081019050919050565b60005b8381101561021a5780820151818401526020810190506101ff565b83811115610229576000848401525b50505050565b6000600282049050600182168061024757607f821691505b6020821081141561025b5761025a610261565b5b50919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61045e806102ce6000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063a41368621461003b578063cfae321714610057575b600080fd5b6100556004803603810190610050919061022c565b610075565b005b61005f61008f565b60405161006c91906102a6565b60405180910390f35b806000908051906020019061008b929190610121565b5050565b60606000805461009e90610387565b80601f01602080910402602001604051908101604052809291908181526020018280546100ca90610387565b80156101175780601f106100ec57610100808354040283529160200191610117565b820191906000526020600020905b8154815290600101906020018083116100fa57829003601f168201915b5050505050905090565b82805461012d90610387565b90600052602060002090601f01602090048101928261014f5760008555610196565b82601f1061016857805160ff1916838001178555610196565b82800160010185558215610196579182015b8281111561019557825182559160200191906001019061017a565b5b5090506101a391906101a7565b5090565b5b808211156101c05760008160009055506001016101a8565b5090565b60006101d76101d2846102f9565b6102c8565b9050828152602081018484840111156101ef57600080fd5b6101fa848285610345565b509392505050565b600082601f83011261021357600080fd5b81356102238482602086016101c4565b91505092915050565b60006020828403121561023e57600080fd5b600082013567ffffffffffffffff81111561025857600080fd5b61026484828501610202565b91505092915050565b600061027882610329565b6102828185610334565b9350610292818560208601610354565b61029b81610417565b840191505092915050565b600060208201905081810360008301526102c0818461026d565b905092915050565b6000604051905081810181811067ffffffffffffffff821117156102ef576102ee6103e8565b5b8060405250919050565b600067ffffffffffffffff821115610314576103136103e8565b5b601f19601f8301169050602081019050919050565b600081519050919050565b600082825260208201905092915050565b82818337600083830152505050565b60005b83811015610372578082015181840152602081019050610357565b83811115610381576000848401525b50505050565b6000600282049050600182168061039f57607f821691505b602082108114156103b3576103b26103b9565b5b50919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f830116905091905056fea2646970667358221220af0cead5c5ad743931b58fac6cd7efea17fd6d09243ade803c9592fe3718a71864736f6c63430008000033000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116dc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6ad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a52a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de13600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060ceebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1e455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d52f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021e4b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10d2f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb1a192fabce13988b84994d4296e6cdc418d55e2f1d7f942188d4040b94fc57ac7880aec93413f117ef14bd4e6d130875ab2c7d7d55a064fac3c2f7bd515163807f8b6b088b6d74c2852fc86c796dca07b44eed6fb3daf5e6b59f7c364db14528789bcdf275fa270780a52ae3b79bb1ce0fda7e0aaad87b57b74bb99ac290714a")))
}

// Block struct to hold all Client fields.
type orderedBlockClients struct {
	primeClient      *ethclient.Client
	primeAvailable   bool
	primeAccount     accounts.Account
	regionClients    []*ethclient.Client
	regionsAvailable []bool
	regionAccounts   []accounts.Account
	zoneClients      [][]*ethclient.Client
	zonesAvailable   [][]bool
	zoneAccounts     [][]accounts.Account
}

// getNodeClients takes in a config and retrieves the Prime, Region, and Zone client
// that is used for mining in a slice.
func getNodeClients(config util.Config) orderedBlockClients {

	// initializing all the clients
	allClients := orderedBlockClients{
		primeAvailable:   false,
		regionClients:    make([]*ethclient.Client, 3),
		regionsAvailable: make([]bool, 3),
		regionAccounts:   make([]accounts.Account, 3),
		zoneClients:      make([][]*ethclient.Client, 3),
		zonesAvailable:   make([][]bool, 3),
		zoneAccounts:     make([][]accounts.Account, 3),
	}

	for i := range allClients.zoneClients {
		allClients.zoneClients[i] = make([]*ethclient.Client, 3)
	}
	for i := range allClients.zonesAvailable {
		allClients.zonesAvailable[i] = make([]bool, 3)
	}
	for i := range allClients.zoneClients {
		allClients.zoneAccounts[i] = make([]accounts.Account, 3)
	}

	// add Prime to orderedBlockClient array at [0]
	if config.PrimeURL != "" {
		primeClient, err := ethclient.Dial(config.PrimeURL)
		if err != nil {
			fmt.Println("Unable to connect to node:", "Prime", config.PrimeURL)
		} else {
			allClients.primeClient = primeClient
			allClients.primeAvailable = true
		}
	}

	// loop to add Regions to orderedBlockClient
	// remember to set true value for Region to be mined
	for i, regionURL := range config.RegionURLs {
		if regionURL != "" {
			regionClient, err := ethclient.Dial(regionURL)
			if err != nil {
				fmt.Println("Unable to connect to node:", "Region", i+1, regionURL)
				allClients.regionsAvailable[i] = false
			} else {
				allClients.regionsAvailable[i] = true
				allClients.regionClients[i] = regionClient
			}
		}
	}

	// loop to add Zones to orderedBlockClient
	// remember ZoneURLS is a 2D array
	for i, zonesURLs := range config.ZoneURLs {
		for j, zoneURL := range zonesURLs {
			if zoneURL != "" {
				zoneClient, err := ethclient.Dial(zoneURL)
				if err != nil {
					fmt.Println("Unable to connect to node:", "Zone", i+1, j+1, zoneURL)
					allClients.zonesAvailable[i][j] = false
				} else {
					allClients.zonesAvailable[i][j] = true
					allClients.zoneClients[i][j] = zoneClient
				}
			}
		}
	}
	return allClients
}

func addAccToClient(clients *orderedBlockClients, acc accounts.Account, i int) {
	switch i {
	case 0:
		common.NodeLocation = []byte{}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.primeAccount = acc
	case 1:
		common.NodeLocation = []byte{0}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.regionAccounts[0] = acc
	case 2:
		common.NodeLocation = []byte{0, 0}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.zoneAccounts[0][0] = acc
	case 3:
		common.NodeLocation = []byte{0, 1}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.zoneAccounts[0][1] = acc
	case 4:
		common.NodeLocation = []byte{0, 2}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.zoneAccounts[0][2] = acc
	case 5:
		common.NodeLocation = []byte{1}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.regionAccounts[1] = acc
	case 6:
		common.NodeLocation = []byte{1, 0}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.zoneAccounts[1][0] = acc
	case 7:
		common.NodeLocation = []byte{1, 1}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.zoneAccounts[1][1] = acc
	case 8:
		common.NodeLocation = []byte{1, 2}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.zoneAccounts[1][2] = acc
	case 9:
		common.NodeLocation = []byte{2}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.regionAccounts[2] = acc
	case 10:
		common.NodeLocation = []byte{2, 0}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.zoneAccounts[2][0] = acc
	case 11:
		common.NodeLocation = []byte{2, 1}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.zoneAccounts[2][1] = acc
	case 12:
		common.NodeLocation = []byte{2, 2}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope")
		}
		clients.zoneAccounts[2][2] = acc
	default:
		fmt.Println("Error adding account to client, chain not found " + fmt.Sprint(i))
	}
}

func Location(a common.Address) *common.Location {

	// Search zone->region->prime address spaces in-slice first, and then search
	// zone->region out-of-slice address spaces next. This minimizes expected
	// search time under the following assumptions:
	// * a node is more likely to encounter a TX from its slice than from another
	// * we expect `>= Z` `zone` TXs for every `region` TX
	// * we expect `>= R` `region` TXs for every `prime` TX
	// * (and by extension) we expect `>= R*Z` `zone` TXs for every `prime` TX
	primeChecked := false
	for r := 0; r < common.NumRegionsInPrime; r++ {
		for z := 0; z < common.NumZonesInRegion; z++ {
			l := common.Location{byte(r), byte(z)}
			if l.ContainsAddress(a) {
				return &l
			}
		}
		l := common.Location{byte(r)}
		if l.ContainsAddress(a) {
			return &l
		}
		// Check prime on first pass through slice, but not again
		if !primeChecked {
			primeChecked = true
			l := common.Location{}
			if l.ContainsAddress(a) {
				return &l
			}
		}
	}
	return nil
}
