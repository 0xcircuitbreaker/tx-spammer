package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	random "math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
	accounts "github.com/dominant-strategies/quai-accounts"
	"github.com/dominant-strategies/quai-accounts/keystore"
	"github.com/dominant-strategies/tx-spammer/util"
	"github.com/sasha-s/go-deadlock"
)

var (
	MAXFEE   = big.NewInt(4 * params.GWei)
	MINERTIP = big.NewInt(2 * params.GWei)
	GAS      = uint64(21000)
	VALUE    = big.NewInt(1)
	// Change the params to the proper chain config
	PARAMS             = params.LocalChainConfig
	WALLETSPERBLOCK    = 160
	NUMZONES           = 9
	enableSleepPerTx   = true
	startingSleepPerTx = 20 * time.Millisecond
	targetTPS          = 30
	exit               = make(chan bool)
)

type wallet struct {
	Address    string `json:"address"`
	Index      int    `json:"index"`
	Path       string `json:"path"`
	PrivateKey string `json:"privateKey"`
}

func main() {
	group := os.Args[1]
	jsonFile, err := os.Open("wallets.json")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var result map[string]map[string][]wallet
	err = json.Unmarshal(byteValue, &result)
	if err != nil {
		fmt.Println(err)
		return
	}
	//addresses_0 := result["group-"+group]["zone-0-0"]
	//fmt.Printf("addresses_0: %v\n", addresses_0)
	//GenerateKeys()
	SpamTxs(result, group)
	//GeneratePrivKeyAndSpam()
	<-exit
}

type AddressCache struct {
	addresses [][]chan common.Address
	privKeys  [][]chan ecdsa.PrivateKey
}

func SpamTxs(wallets map[string]map[string][]wallet, group string) {
	config, err := util.LoadConfig(".")
	if err != nil {
		fmt.Println("cannot load config: " + err.Error())
		return
	}
	allClients := getNodeClients(config)
	region := -1
	for i := 0; i < NUMZONES; i++ {
		from_zone := i % 3
		if i%3 == 0 {
			region++
		}

		go func(from_zone int, region int) {
			if !allClients.zonesAvailable[region][from_zone] {
				return
			}
			client := allClients.zoneClients[region][from_zone]
			signer := types.LatestSigner(PARAMS)
			zoneWallets := wallets["group-"+group]["zone-"+fmt.Sprintf("%d-%d", region, from_zone)]
			walletIndex := 0
			walletsPerBlock := WALLETSPERBLOCK
			txsSent := 0
			nonces := make(map[common.AddressBytes]uint64)
			var sleepPerTx time.Duration
			sleepPerTx = startingSleepPerTx
			errCount := 0
			shouldWalkUp := true

			start := time.Now()
			walkUpTime := time.Now()
			for x := 0; true; x++ {
				pendingTxCount, queuedTxCount := client.PoolStatus(context.Background())

				fmt.Println("pending uint", uint64(pendingTxCount), "queued", uint64(queuedTxCount))
				if err != nil || pendingTxCount > 5000 {
					time.Sleep(1 * time.Second)
					continue
				}
				fromAddr := common.HexToAddress(zoneWallets[walletIndex].Address)
				fromPrivKey, err := crypto.ToECDSA(common.FromHex(zoneWallets[walletIndex].PrivateKey))
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				var nonce uint64
				var exists bool
				if nonce, exists = nonces[fromAddr.Bytes20()]; !exists {
					nonce, err := client.PendingNonceAt(context.Background(), fromAddr)
					if err != nil {
						fmt.Println(err.Error())
						if walletIndex < len(zoneWallets)-1 {
							walletIndex++
						} else {
							walletIndex = 0
						}
						continue // try the next wallet
					}
					nonces[fromAddr.Bytes20()] = nonce
				}

				var toAddr common.Address
				var tx *types.Transaction
				if x%5 == 0 { // Change to true for all ETXs
					otherZone := wallets["group-"+group]["zone-"+fmt.Sprintf("%d-%d", region, (from_zone+1)%3)] // Cross Region
					toAddr = common.HexToAddress(otherZone[len(zoneWallets)-1-walletIndex].Address)
					inner_tx := types.InternalToExternalTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: MAXFEE, ETXGasPrice: new(big.Int).Mul(MAXFEE, big.NewInt(2)), ETXGasLimit: 21000, ETXGasTip: new(big.Int).Mul(MINERTIP, big.NewInt(2)), Gas: GAS * 2, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
					tx = types.NewTx(&inner_tx)
				} else if x%9 == 0 {
					otherRegion := wallets["group-"+group]["zone-"+fmt.Sprintf("%d-%d", (region+1)%3, (from_zone+1)%3)] // Cross Prime
					toAddr = common.HexToAddress(otherRegion[len(zoneWallets)-1-walletIndex].Address)
					inner_tx := types.InternalToExternalTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: MAXFEE, ETXGasPrice: new(big.Int).Mul(MAXFEE, big.NewInt(2)), ETXGasLimit: 21000, ETXGasTip: new(big.Int).Mul(MINERTIP, big.NewInt(2)), Gas: GAS * 2, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
					tx = types.NewTx(&inner_tx)
				} else {
					toAddr = common.HexToAddress(zoneWallets[len(zoneWallets)-1-walletIndex].Address)
					inner_tx := types.InternalTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: MAXFEE, Gas: GAS, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
					tx = types.NewTx(&inner_tx)
				}
				tx, err = types.SignTx(tx, signer, fromPrivKey)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				err = client.SendTransaction(context.Background(), tx)
				if err != nil {
					fmt.Printf("zone-" + fmt.Sprintf("%d-%d", region, from_zone) + ": " + err.Error() + "\n")
					if err.Error() == core.ErrReplaceUnderpriced.Error() {
						inner_tx := types.InternalTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: new(big.Int).Mul(big.NewInt(2), MINERTIP), GasFeeCap: new(big.Int).Mul(big.NewInt(2), MAXFEE), Gas: GAS, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
						tx = types.NewTx(&inner_tx)
						tx, err = types.SignTx(tx, signer, fromPrivKey)
						if err != nil {
							fmt.Println(err.Error())
							return
						}
						err = client.SendTransaction(context.Background(), tx)
						if err != nil {
							walletIndex++
							errCount++
							time.Sleep(time.Second * time.Duration(errCount))
						}
					} else if err.Error() == core.ErrNonceTooLow.Error() {
						nonces[fromAddr.Bytes20()]++ // optional: ask the node for the correct pending nonce
						continue                     // do not increment walletIndex, try again with the same wallet
					} else if err.Error() == core.ErrInsufficientFunds.Error() {
						if walletIndex < len(zoneWallets)-1 {
							walletIndex++
						} else {
							walletIndex = 0
						}
						continue // try the next wallet
					} else {
						errCount++
						time.Sleep(time.Second * time.Duration(errCount))
					}
				} else {
					if enableSleepPerTx {
						if sleepPerTx != time.Duration(0) {
							randomNanoseconds := random.Intn(int(sleepPerTx.Nanoseconds()))
							time.Sleep(time.Duration(randomNanoseconds * 2))
						}
					}
					errCount = 0
				}
				if walletIndex < len(zoneWallets)-1 {
					walletIndex++
				} else {
					walletIndex = 0
				}
				txsSent++
				nonces[fromAddr.Bytes20()]++

				if txsSent%walletsPerBlock == 0 && walletIndex != 0 { // not perfect math in the case that walletIndex wraps around to zero
					elapsed := time.Since(start)
					tps := float64(walletsPerBlock) / elapsed.Seconds()
					fmt.Printf("zone-"+fmt.Sprintf("%d-%d", region, from_zone)+": Time elapsed for %d txs: %d ms\n", walletsPerBlock, elapsed.Milliseconds())
					fmt.Printf("zone-"+fmt.Sprintf("%d-%d", region, from_zone)+": TPS: %f\n", tps)
					fmt.Printf("zone-"+fmt.Sprintf("%d-%d", region, from_zone)+": Txs Sent: %d\n", txsSent)

					tpsInNS := float64(walletsPerBlock) / float64(elapsed.Seconds())
					newSleepBasedOnCalcTPS := float64(sleepPerTx.Nanoseconds()) + (float64(sleepPerTx.Nanoseconds()) * float64(tpsInNS-float64(targetTPS)) * 0.01) // newSleep = oldSleep * (tps / targetTPS)
					fmt.Println("controller:", "old", sleepPerTx.Seconds(), "Error", float64(tpsInNS-float64(targetTPS)), "new", newSleepBasedOnCalcTPS)
					sleepPerTx = time.Duration(math.Max(newSleepBasedOnCalcTPS, 0))
					fmt.Printf("zone-"+fmt.Sprintf("%d-%d", region, from_zone)+": New Sleep: %d ms\n", sleepPerTx.Milliseconds())
					start = time.Now()

					if tps > float64(targetTPS) {
						shouldWalkUp = false
					} else {
						shouldWalkUp = true
					}
				}
				if time.Since(walkUpTime) >= 100*time.Second && int(float64(walletsPerBlock)*1.1) < len(zoneWallets) && shouldWalkUp {
					walletsPerBlock = int(float64(walletsPerBlock) * 1.1)
					walkUpTime = time.Now()
				}

			}
		}(from_zone, region)
	}
}

func GeneratePrivKeyAndSpam() {
	addrCache := &AddressCache{
		addresses: make([][]chan common.Address, 3),
		privKeys:  make([][]chan ecdsa.PrivateKey, 3),
	}
	for i := range addrCache.addresses {
		addrCache.addresses[i] = make([]chan common.Address, 3)
		for x := range addrCache.addresses[i] {
			addrCache.addresses[i][x] = make(chan common.Address, 1000000)
		}
	}
	for i := range addrCache.privKeys {
		addrCache.privKeys[i] = make([]chan ecdsa.PrivateKey, 3)
		for x := range addrCache.privKeys[i] {
			addrCache.privKeys[i][x] = make(chan ecdsa.PrivateKey, 1000000)
		}
	}
	go GenerateAddresses(addrCache)
	time.Sleep(time.Second * 5)
	config, err := util.LoadConfig(".")
	if err != nil {
		fmt.Println("cannot load config: " + err.Error())
		return
	}
	allClients := getNodeClients(config)

	region := -1
	for i := 0; i < 1; i++ {
		from_zone := i % 3
		if i%3 == 0 {
			region++
		}
		addrCache.addresses = append(addrCache.addresses, make([]chan common.Address, 0, 0))
		go func(from_zone int, region int, addrCache *AddressCache) {
			if !allClients.zonesAvailable[region][from_zone] {
				return
			}
			client := allClients.zoneClients[region][from_zone]
			signer := types.LatestSigner(PARAMS)
			var toAddr common.Address
			start1 := time.Now()
			start2 := time.Now()
			for x := 0; true; x++ {
				fromKey := <-addrCache.privKeys[region][from_zone]
				var tx *types.Transaction
				if x%1000 == 0 && x != 0 {
					fmt.Println("Time elapsed for 1000 txs in ms: ", time.Since(start2).Milliseconds())
					start2 = time.Now()
				}
				if x%5 == 0 { // Change to true for all ETXs
					toAddr = ChooseRandomETXAddress(addrCache, region, from_zone)
					// Change the params
					inner_tx := types.InternalToExternalTx{ChainID: PARAMS.ChainID, Nonce: 0, GasTipCap: MINERTIP, GasFeeCap: MAXFEE, ETXGasPrice: new(big.Int).Mul(MAXFEE, big.NewInt(2)), ETXGasLimit: 21000, ETXGasTip: new(big.Int).Mul(MINERTIP, big.NewInt(2)), Gas: GAS * 2, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
					tx = types.NewTx(&inner_tx)
				} else {
					// Change the params
					toAddr = <-addrCache.addresses[region][from_zone]
					toAddr = <-addrCache.addresses[region][from_zone] // twice so we don't send to the same address
					inner_tx := types.InternalTx{ChainID: PARAMS.ChainID, Nonce: 0, GasTipCap: MINERTIP, GasFeeCap: MAXFEE, Gas: GAS, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
					tx = types.NewTx(&inner_tx)
				}
				tx, err = types.SignTx(tx, signer, &fromKey)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				err = client.SendTransaction(context.Background(), tx)
				if err != nil {
					fmt.Println(err.Error())
				}
				time.Sleep(5000 * time.Millisecond)
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
			addrCache.privKeys[location.Region()][location.Zone()] <- *privKey
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
	zoneWallets      [][]wallet
	walletLock       deadlock.RWMutex
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
