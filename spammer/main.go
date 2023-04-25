package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	random "math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
	accounts "github.com/dominant-strategies/quai-accounts"
	"github.com/dominant-strategies/quai-accounts/keystore"
	"github.com/dominant-strategies/tx-spammer/util"
)

var (
	MAXFEE    = big.NewInt(4 * params.GWei)
	MINERTIP  = big.NewInt(2 * params.GWei)
	GAS       = uint64(21000)
	VALUE     = big.NewInt(1)
	PARAMS    = params.OrchardChainConfig
	from_zone = 0
	exit      = make(chan bool)
)

func main() {
	//GenerateKeys()
	SpamTxs()
	<-exit
}

type AddressCache struct {
	addresses [][]chan common.Address
}

func SpamTxs() {
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

			var toAddr common.Address
			nonce, err := client.PendingNonceAt(context.Background(), from.Address)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			balance, _ := client.BalanceAt(context.Background(), from.Address, nil)
			fmt.Println("address: ", from.Address.String())
			//temp, _ := big.NewFloat(10e18).Int(nil)
			fmt.Println("Balance: ", balance.String())
			nonceCounter := 0
			start1 := time.Now()
			start2 := time.Now()
			for x := 0; true; x++ {
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
					inner_tx := types.InternalToExternalTx{ChainID: PARAMS.ChainID, Nonce: nonce + uint64(nonceCounter), GasTipCap: MINERTIP, GasFeeCap: MAXFEE, ETXGasPrice: new(big.Int).Mul(MAXFEE, big.NewInt(2)), ETXGasLimit: 21000, ETXGasTip: new(big.Int).Mul(MINERTIP, big.NewInt(2)), Gas: GAS * 2, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
					tx = types.NewTx(&inner_tx)
				} else {
					// Change the params
					toAddr = <-addrCache.addresses[region][from_zone]
					inner_tx := types.InternalTx{ChainID: PARAMS.ChainID, Nonce: nonce + uint64(nonceCounter), GasTipCap: MINERTIP, GasFeeCap: MAXFEE, Gas: GAS, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
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
				}
				time.Sleep(50 * time.Millisecond)
				nonceCounter++
			}
			elapsed := time.Since(start1)
			fmt.Println("Time elapsed for all txs in ms: ", elapsed.Milliseconds())
		}(from_zone, region, addrCache)
	}
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

func GenerateAddresses(addrCache *AddressCache) {
	for {
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

// Block struct to hold all Client fields.
type orderedBlockClients struct {
	primeClient      *ethclient.Client
	primeAvailable   bool
	regionClients    []*ethclient.Client
	regionsAvailable []bool
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
		common.NodeLocation = []byte{0, 0}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope" + acc.Address.String())
		}
		clients.zoneAccounts[0][0] = acc
	case 1:
		common.NodeLocation = []byte{0, 1}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope" + acc.Address.String())
		}
		clients.zoneAccounts[0][1] = acc
	case 2:
		common.NodeLocation = []byte{0, 2}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope" + acc.Address.String())
		}
		clients.zoneAccounts[0][2] = acc
	case 3:
		common.NodeLocation = []byte{1, 0}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope" + acc.Address.String())
		}
		clients.zoneAccounts[1][0] = acc
	case 4:
		common.NodeLocation = []byte{1, 1}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope" + acc.Address.String())
		}
		clients.zoneAccounts[1][1] = acc
	case 5:
		common.NodeLocation = []byte{1, 2}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope" + acc.Address.String())
		}
		clients.zoneAccounts[1][2] = acc
	case 6:
		common.NodeLocation = []byte{2, 0}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope" + acc.Address.String())
		}
		clients.zoneAccounts[2][0] = acc
	case 7:
		common.NodeLocation = []byte{2, 1}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope" + acc.Address.String())
		}
		clients.zoneAccounts[2][1] = acc
	case 8:
		common.NodeLocation = []byte{2, 2}
		if !common.IsInChainScope(acc.Address.Bytes()) {
			panic("Account not in chain scope" + acc.Address.String())
		}
		clients.zoneAccounts[2][2] = acc
	default:
		panic("Error adding account to client, chain not found " + fmt.Sprint(i) + acc.Address.String())
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

func GenerateKeys() {
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
