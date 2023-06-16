package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"io"
	"math"
	"math/big"
	random "math/rand"
	"os"
	"time"

	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
	accounts "github.com/dominant-strategies/quai-accounts"
	"github.com/dominant-strategies/tx-spammer/util"
	"github.com/sasha-s/go-deadlock"
)

var (
	MAXFEE   = big.NewInt(4 * params.GWei)
	MINERTIP = big.NewInt(2 * params.GWei)
	GAS      = uint64(21000)
	VALUE    = big.NewInt(1)
	// Change the params to the proper chain config
	WALLETSPERBLOCK    = 1360
	enableSleepPerTx   = true
	startingSleepPerTx = 20 * time.Millisecond
	targetTPS          = 18
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

	host := "localhost"
	if len(os.Args) > 2 {
		host = os.Args[2]
	}

	jsonFile, err := os.Open("wallets.json")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer jsonFile.Close()
	byteValue, _ := io.ReadAll(jsonFile)
	var result map[string]map[string][]wallet
	err = json.Unmarshal(byteValue, &result)
	if err != nil {
		panic(fmt.Errorf("error parsing wallets.json: %v", err))
		return
	}
	SpamTxs(result, group, host)
	<-exit
}

func SpamTxs(wallets map[string]map[string][]wallet, group string, host string) {
	config, err := util.LoadConfig(host)
	rand := random.New(random.NewSource(time.Now().UnixNano()))
	fmt.Println("config loaded", config)
	if err != nil {
		fmt.Println("cannot load config: " + err.Error())
		return
	}
	allClients := getNodeClients(config, host)
	for zone, client := range allClients.zoneClients {
		go func(zone string, client *ethclient.Client) {
			otherZones := make([]string, 0)
			for k := range config.Ports {
				if k != zone {
					otherZones = append(otherZones, k)
				}
			}
			signer := types.LatestSigner(
				&params.ChainConfig{ChainID: big.NewInt(config.ChainId)},
			)
			zoneWallets := wallets["group-"+group][zone]
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
				pendingTxCount, pendingTxQueue := client.PoolStatus(context.Background())

				if err != nil || (pendingTxCount+pendingTxQueue) > 5000 {
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
					nonce, err = client.PendingNonceAt(context.Background(), fromAddr)
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
				var inner_tx types.TxData
				if x%5 == 0 { // Change to true for all ETXs
					otherZone := otherZones[rand.Intn(len(otherZones))] // random value from otherZones
					toAddr = common.HexToAddress(wallets["group-"+group][otherZone][rand.Intn(len(wallets["group-"+group][otherZone]))].Address)
					inner_tx = &types.InternalToExternalTx{ChainID: big.NewInt(config.ChainId), Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: MAXFEE, ETXGasPrice: new(big.Int).Mul(MAXFEE, big.NewInt(2)), ETXGasLimit: 21000, ETXGasTip: new(big.Int).Mul(MINERTIP, big.NewInt(2)), Gas: GAS * 2, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
				} else {
					toAddr = common.HexToAddress(zoneWallets[len(zoneWallets)-1-walletIndex].Address)
					inner_tx = &types.InternalTx{ChainID: big.NewInt(config.ChainId), Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: MAXFEE, Gas: GAS, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
				}
				tx = types.NewTx(inner_tx)
				tx, err = types.SignTx(tx, signer, fromPrivKey)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				if err != nil {
					fmt.Printf(zone + ": " + err.Error() + "\n")
					if err.Error() == core.ErrReplaceUnderpriced.Error() {
						inner_tx := types.InternalTx{ChainID: big.NewInt(config.ChainId), Nonce: nonce, GasTipCap: new(big.Int).Mul(big.NewInt(2), MINERTIP), GasFeeCap: new(big.Int).Mul(big.NewInt(2), MAXFEE), Gas: GAS, To: &toAddr, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
						tx = types.NewTx(&inner_tx)
						tx, err = types.SignTx(tx, signer, fromPrivKey)
						if err != nil {
							fmt.Println(err.Error())
							return
						}
						err = client.SendTransaction(context.Background(), tx)
						if err != nil {
							fmt.Println(err.Error())
							walletIndex++
							errCount++
							time.Sleep(time.Second * time.Duration(errCount))
						}
					} else if err.Error() == core.ErrNonceTooLow.Error() {
						nonces[fromAddr.Bytes20()]++ // optional: ask the node for the correct pending nonce
						continue                     // do not increment walletIndex, try again with the same wallet
					} else if err.Error() == core.ErrInsufficientFunds.Error() {
						fmt.Println(err.Error())
						if walletIndex < len(zoneWallets)-1 {
							walletIndex++
						} else {
							walletIndex = 0
						}
						continue // try the next wallet
					} else {
						fmt.Println(err.Error())
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
					fmt.Printf(zone+": Time elapsed for %d txs: %d ms TPS: %f Txs Sent: %d ", walletsPerBlock, elapsed.Milliseconds(), tps, txsSent)

					tpsInNS := float64(walletsPerBlock) / float64(elapsed.Seconds())
					newSleepBasedOnCalcTPS := float64(sleepPerTx.Nanoseconds()) + (float64(sleepPerTx.Nanoseconds()) * float64(tpsInNS-float64(targetTPS)) * 0.01) // newSleep = oldSleep * (tps / targetTPS)
					fmt.Println("controller:", "old", sleepPerTx.Seconds(), "Error", float64(tpsInNS-float64(targetTPS)), "new", newSleepBasedOnCalcTPS)
					sleepPerTx = time.Duration(math.Max(newSleepBasedOnCalcTPS, 0))
					fmt.Printf(zone+": New Sleep: %d ms\n", sleepPerTx.Milliseconds())
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
		}(zone, client)
	}
}

// Block struct to hold all Client fields.
type orderedBlockClients struct {
	zoneClients  map[string]*ethclient.Client
	zoneAccounts [][]accounts.Account
	zoneWallets  [][]wallet
	walletLock   deadlock.RWMutex
}

// getNodeClients takes in a config and retrieves the Prime, Region, and Zone client
// that is used for mining in a slice.
func getNodeClients(config util.Config, host string) orderedBlockClients {

	// initializing all the clients
	allClients := orderedBlockClients{
		zoneClients:  make(map[string]*ethclient.Client, 3),
		zoneAccounts: make([][]accounts.Account, 3),
	}

	for zone, ports := range config.Ports {
		zoneClient, err := ethclient.Dial(fmt.Sprintf("ws://%s:%d", host, ports.Ws))
		if err != nil {
			delete(allClients.zoneClients, zone)
		}
		allClients.zoneClients[zone] = zoneClient
	}
	return allClients
}
