package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/TwiN/go-color"
	lru "github.com/hashicorp/golang-lru"
	"github.com/spruce-solutions/go-quai/common"
	"github.com/spruce-solutions/go-quai/common/hexutil"
	"github.com/spruce-solutions/go-quai/consensus/blake3"
	"github.com/spruce-solutions/go-quai/core/types"
	"github.com/spruce-solutions/go-quai/crypto"
	"github.com/spruce-solutions/go-quai/ethclient"
	"github.com/spruce-solutions/quai-manager/manager/util"
)

const (
	// resultQueueSize is the size of channel listening to sealing result.
	resultQueueSize = 10
)

var (
	big2e256 = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), big.NewInt(0)) // 2^256
)

var exit = make(chan bool)
var Reset = "\033[0m"
var Red = "\033[31m"
var Green = "\033[32m"
var Yellow = "\033[33m"
var Blue = "\033[34m"
var Purple = "\033[35m"
var Cyan = "\033[36m"
var Gray = "\033[37m"
var White = "\033[97m"

func init() {
	if runtime.GOOS == "windows" {
		Reset = ""
		Red = ""
		Green = ""
		Yellow = ""
		Blue = ""
		Purple = ""
		Cyan = ""
		Gray = ""
		White = ""
	}
}

type Manager struct {
	engine *blake3.Blake3

	orderedBlockClients orderedBlockClients // will hold all chain URLs and settings in order from prime to zone-3-3
	combinedHeader      *types.Header
	pendingBlocks       []*types.ReceiptBlock // Current pending blocks of the manager
	lock                sync.Mutex
	location            []byte

	pendingZoneBlockCh chan *types.ReceiptBlock

	updatedCh chan *types.Header
	resultCh  chan *types.Header
	startCh   chan struct{}
	exitCh    chan struct{}
	doneCh    chan bool // channel for updating location

	BlockCache [][]*lru.Cache // Cache for the most recent entire blocks
}

// Block struct to hold all Client fields.
type orderedBlockClients struct {
	primeClient      *ethclient.Client
	primeAvailable   bool
	regionClients    []*ethclient.Client
	regionsAvailable []bool
	zoneClients      [][]*ethclient.Client
	zonesAvailable   [][]bool
}

var exponentialBackoffCeilingSecs int64 = 14400 // 4 hours

func main() {
	config, err := util.LoadConfig("..")
	if err != nil {
		log.Fatal("cannot load config:", err)
	}

	lastUpdatedAt := time.Now()
	attempts := 0

	// errror handling in case any connections failed
	connectStatus := false
	// Get URLs for all chains and set mining bools to represent if online
	// getting clients comes first because manager can poll chains for auto-mine
	allClients := getNodeClients(config)

	for !connectStatus {
		if time.Now().Sub(lastUpdatedAt).Hours() >= 12 {
			attempts = 0
		}

		connectStatus = true
		if !allClients.primeAvailable {
			connectStatus = false
		}
		for _, status := range allClients.regionsAvailable {
			if !status {
				connectStatus = false
			}
		}
		for _, zonesArray := range allClients.zonesAvailable {
			for _, status := range zonesArray {
				if !status {
					connectStatus = false
				}
			}
		}
		lastUpdatedAt = time.Now()
		attempts += 1

		// exponential back-off implemented
		delaySecs := int64(math.Floor((math.Pow(2, float64(attempts)) - 1) * 0.5))
		if delaySecs > exponentialBackoffCeilingSecs {
			delaySecs = exponentialBackoffCeilingSecs
		}

		// should only get here if the ffmpeg record stream process dies
		fmt.Printf("This is attempt %d to connect to all go-quai nodes. Waiting %d seconds and then retrying...\n", attempts, delaySecs)

		time.Sleep(time.Duration(delaySecs) * time.Second)

		allClients = getNodeClients(config)
	}

	if !connectStatus {
		log.Println("Some or all connections to chains not available")
		log.Println("For best performance check your connections and restart the manager")
	}

	// variable to check whether mining location is set manually or automatically
	var changeLocationCycle bool

	// set mining location
	// if using the run-mine command then must remember to set region and zone locations
	// if using run then the manager will automatically follow the chain with lowest difficulty
	if len(os.Args) > 3 {
		changeLocationCycle = false
		location := os.Args[1:3]
		mine, _ := strconv.Atoi(os.Args[3:][0])

		// error management to check correct number of values provided
		if len(location) == 0 {
			log.Fatal("Please mention location where you want to mine")
		}
		if len(location) == 1 {
			log.Fatal("You are missing either Region or Zone location")
		}
		if len(location) > 2 {
			log.Fatal("Only specify 2 values for the location")
		}

		// converting region and zone location values from string to integer
		regionLoc, _ := strconv.Atoi(location[0])
		zoneLoc, _ := strconv.Atoi(location[1])

		// converting region and zone integer values to bytes
		RegionLocArr := make([]byte, 8)
		ZoneLocArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(RegionLocArr, uint64(regionLoc))
		binary.LittleEndian.PutUint64(ZoneLocArr, uint64(zoneLoc))

		config.Location = []byte{RegionLocArr[0], ZoneLocArr[0]}
		config.Mine = mine == 1
		log.Println(color.Ize(color.Red, "Manual mode started"))
	} else {
		if config.Auto && config.Mine { // auto-miner
			config.Location = findBestLocation(allClients)
			config.Mine = true
			changeLocationCycle = config.Optimize
			fmt.Println("Aut-miner mode started with Optimizer= ", config.Optimize, "and timer set to ", config.OptimizeTimer, "minutes")
		} else { // if run
			changeLocationCycle = false
			location := config.Location

			if len(location) != 2 {
				log.Fatal("Only specify 2 values for the location")
				fmt.Println("Make sure to set config.yaml file properly")
			}
			fmt.Println("Listening mode started")
		}
	}

	header := &types.Header{
		ParentHash:        make([]common.Hash, 3),
		Number:            make([]*big.Int, 3),
		Extra:             make([][]byte, 3),
		Time:              uint64(0),
		BaseFee:           make([]*big.Int, 3),
		GasLimit:          make([]uint64, 3),
		Coinbase:          make([]common.Address, 3),
		Difficulty:        make([]*big.Int, 3),
		NetworkDifficulty: make([]*big.Int, 3),
		Root:              make([]common.Hash, 3),
		TxHash:            make([]common.Hash, 3),
		UncleHash:         make([]common.Hash, 3),
		ReceiptHash:       make([]common.Hash, 3),
		GasUsed:           make([]uint64, 3),
		Bloom:             make([]types.Bloom, 3),
	}

	blake3Config := blake3.Config{
		MiningThreads: 0,
		NotifyFull:    true,
	}

	blake3Engine, err := blake3.New(blake3Config, nil, false)
	if nil != err {
		log.Fatal("Failed to create Blake3 engine: ", err)
	}

	m := &Manager{
		engine:              blake3Engine,
		orderedBlockClients: allClients,
		combinedHeader:      header,
		pendingBlocks:       make([]*types.ReceiptBlock, 3),
		pendingZoneBlockCh:  make(chan *types.ReceiptBlock, resultQueueSize),
		resultCh:            make(chan *types.Header, resultQueueSize),
		updatedCh:           make(chan *types.Header, resultQueueSize),
		exitCh:              make(chan struct{}),
		startCh:             make(chan struct{}, 1),
		doneCh:              make(chan bool),
		location:            config.Location,
	}

	if config.Mine {
		log.Println("Starting manager in location ", config.Location)

		m.subscribeAllPendingBlocks()

		go m.resultLoop()

		go m.miningLoop()

		go m.SubmitHashRate()

		go m.loopGlobalBlock()

		// fetching the pending blocks
		m.fetchAllPendingBlocks()

		if changeLocationCycle {
			go m.checkBestLocation(config.OptimizeTimer)
		}
	}
	<-exit
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
	}

	for i := range allClients.zoneClients {
		allClients.zoneClients[i] = make([]*ethclient.Client, 3)
	}
	for i := range allClients.zonesAvailable {
		allClients.zonesAvailable[i] = make([]bool, 3)
	}

	// add Prime to orderedBlockClient array at [0]
	if config.PrimeURL != "" {
		primeClient, err := ethclient.Dial(config.PrimeURL)
		if err != nil {
			log.Println("Unable to connect to node:", "Prime", config.PrimeURL)
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
				log.Println("Unable to connect to node:", "Region", i+1, regionURL)
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
					log.Println("Unable to connect to node:", "Zone", i+1, j+1, zoneURL)
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

// subscribePendingHeader subscribes to the head of the mining nodes in order to pass
// the most up to date block to the miner within the manager.
func (m *Manager) subscribePendingHeader(client *ethclient.Client, sliceIndex int) {
	log.Println("Current location is ", m.location)
	// check the status of the sync
	checkSync, err := client.SyncProgress(context.Background())

	if err != nil {
		switch sliceIndex {
		case 0:
			log.Println("Error occured while synching to Prime")
		case 1:
			log.Println("Error occured while synching to Region")
		case 2:
			log.Println("Error occured while synching to Zone")
		}
	}

	// wait until sync is nil to continue
	for checkSync != nil && err == nil {
		checkSync, err = client.SyncProgress(context.Background())
		if err != nil {
			log.Println("error during syncing: ", err, checkSync)
		}
	}

	// done channel in case best Location updates
	// subscribe to the pending block only if not synching
	if checkSync == nil && err == nil {
		// Wait for chain events and push them to clients
		header := make(chan *types.Header)
		sub, err := client.SubscribePendingBlock(context.Background(), header)
		if err != nil {
			log.Fatal("Failed to subscribe to pending block events", err)
		}
		defer sub.Unsubscribe()

		// Wait for various events and assing to the appropriate background threads
		for {
			select {
			case <-header:
				// New head arrived, send if for state update if there's none running
				m.fetchPendingBlocks(client, sliceIndex)
			case <-m.doneCh: // location updated and this routine needs to be stopped to start a new one
				break
			}
		}
	}
}

// checkNonceEmpty checks if any of the headers have empty nonce
func checkNonceEmpty(commonHead *types.Header, oldChain, newChain []*types.Header) bool {
	if commonHead.Nonce == (types.BlockNonce{}) {
		return false
	}

	for i := 0; i < len(oldChain); i++ {
		if oldChain[i].Nonce == (types.BlockNonce{}) {
			return false
		}
	}
	for i := 0; i < len(newChain); i++ {
		if newChain[i].Nonce == (types.BlockNonce{}) {
			return false
		}
	}
	return true
}

// PendingBlocks gets the latest block when we have received a new pending header. This will get the receipts,
// transactions, and uncles to be stored during mining.
func (m *Manager) fetchPendingBlocks(client *ethclient.Client, sliceIndex int) {
	var receiptBlock *types.ReceiptBlock
	var err error

	m.lock.Lock()
	receiptBlock, err = client.GetPendingBlock(context.Background())

	// check for stale headers and refetch the latest header
	if receiptBlock != nil && receiptBlock.Header().Number[sliceIndex] == m.combinedHeader.Number[sliceIndex] && err == nil {
		switch sliceIndex {
		case 0:
			log.Println("Expected header numbers don't match for Prime at block height", receiptBlock.Header().Number[0])
			log.Println("Retrying and attempting to refetch the latest header for Prime")
		case 1:
			log.Println("Expected header numbers don't match for Region at block height", receiptBlock.Header().Number[1])
			log.Println("Retrying and attempting to refetch the latest header for Region")
		case 2:
			log.Println("Expected header numbers don't match for Zone at block height", receiptBlock.Header().Number[2])
			log.Println("Retrying and attempting to refetch the latest header for Zone")
		}
		receiptBlock, err = client.GetPendingBlock(context.Background())
	}

	// retrying for 5 times if pending block not found
	if err != nil || receiptBlock == nil {
		log.Println("Pending block not found for index:", sliceIndex, "error:", err)
		found := false
		attempts := 0
		lastUpdatedAt := time.Now()

		for !found {
			if time.Now().Sub(lastUpdatedAt).Hours() >= 12 {
				attempts = 0
			}

			receiptBlock, err = client.GetPendingBlock(context.Background())
			if err == nil && receiptBlock != nil {
				break
			}
			lastUpdatedAt = time.Now()
			attempts += 1

			// exponential back-off implemented
			delaySecs := int64(math.Floor((math.Pow(2, float64(attempts)) - 1) * 0.5))
			if delaySecs > exponentialBackoffCeilingSecs {
				delaySecs = exponentialBackoffCeilingSecs
			}

			// should only get here if the ffmpeg record stream process dies
			fmt.Printf("This is attempt %d to fetch pending block. Waiting %d seconds and then retrying...\n", attempts, delaySecs)

			time.Sleep(time.Duration(delaySecs) * time.Second)
		}
	}

	m.lock.Unlock()
	switch sliceIndex {
	case 2:
		m.pendingZoneBlockCh <- receiptBlock
	}
}

// updateCombinedHeader performs the merged mining step of combining all headers from the slice of nodes
// being mined. This is then sent to the miner where a valid header is returned upon respective difficulties.
func (m *Manager) updateCombinedHeader(header *types.Header, i int) {
	m.lock.Lock()
	time := header.Time
	if time <= m.combinedHeader.Time {
		time = m.combinedHeader.Time
	}

	m.combinedHeader.ParentHash[i] = header.ParentHash[i]
	m.combinedHeader.UncleHash[i] = header.UncleHash[i]
	m.combinedHeader.Number[i] = header.Number[i]
	m.combinedHeader.Extra[i] = header.Extra[i]
	m.combinedHeader.BaseFee[i] = header.BaseFee[i]
	m.combinedHeader.GasLimit[i] = header.GasLimit[i]
	m.combinedHeader.GasUsed[i] = header.GasUsed[i]
	m.combinedHeader.TxHash[i] = header.TxHash[i]
	m.combinedHeader.ReceiptHash[i] = header.ReceiptHash[i]
	m.combinedHeader.Root[i] = header.Root[i]
	m.combinedHeader.Difficulty[i] = header.Difficulty[i]
	m.combinedHeader.NetworkDifficulty[i] = header.NetworkDifficulty[i]
	m.combinedHeader.Coinbase[i] = header.Coinbase[i]
	m.combinedHeader.Bloom[i] = header.Bloom[i]
	m.combinedHeader.Time = time
	m.combinedHeader.Location = m.location
	m.lock.Unlock()
}

// loopGlobalBlock takes in updates from the pending headers and blocks in order to update the miner.
// This sets the header information and puts the block data inside of pendingBlocks so that it can be retrieved
// upon a successful nonce being found.
func (m *Manager) loopGlobalBlock() error {
	for {
		select {
		case block := <-m.pendingZoneBlockCh:
			header := block.Header()
			m.updateCombinedHeader(header, 0)
			m.updateCombinedHeader(header, 1)
			m.updateCombinedHeader(header, 2)
			m.pendingBlocks[2] = block
			header.Nonce = types.BlockNonce{}
			select {
			case m.updatedCh <- m.combinedHeader:
			default:
				log.Println("Sealing result is not read by miner", "mode", "fake", "sealhash")
			}
		}
	}
}

// miningLoop iterates on a new header and passes the result to m.resultCh. The result is called within the method.
func (m *Manager) miningLoop() error {
	var (
		stopCh chan struct{}
	)
	// interrupt aborts the in-flight sealing task.
	interrupt := func() {
		if stopCh != nil {
			close(stopCh)
			stopCh = nil
		}
	}
	for {
		select {
		case header := <-m.updatedCh:
			// Mine the header here
			// Return the valid header with proper nonce and mix digest
			// Interrupt previous sealing operation
			interrupt()
			stopCh = make(chan struct{})
			// See if we can grab the lock in order to start mining
			// Lock should be held while sending mined blocks
			// Reduce race conditions while sending mined blocks and waiting for pending headers
			m.lock.Lock()
			m.lock.Unlock()

			log.Println("Starting to mine:  ", header.Number, "location", m.location, "difficulty", header.Difficulty)
			if err := m.engine.SealHeader(header, m.resultCh, stopCh); err != nil {
				log.Println("Block sealing failed", "err", err)
			}
		}
	}
}

// WatchHashRate is a simple method to watch the hashrate of our miner and log the output.
func (m *Manager) SubmitHashRate() {
	ticker := time.NewTicker(60 * time.Second)

	// generating random ID to submit in the SubmitHashRate method
	randomId := rand.Int()
	randomIdArray := make([]byte, 8)
	binary.LittleEndian.PutUint64(randomIdArray, uint64(randomId))
	id := crypto.Keccak256Hash(randomIdArray)

	var null float64 = 0
	go func() {
		for {
			select {
			case <-ticker.C:
				hashRate := m.engine.Hashrate()
				if hashRate != null {
					log.Println("Quai Miner - current hashes per second: ", hashRate)
					m.engine.SubmitHashrate(hexutil.Uint64(hashRate), id)
				}
			}
		}
	}()
}

// resultLoop takes in the result and passes to the proper channels for receiving.
func (m *Manager) resultLoop() error {
	for {
		select {
		case header := <-m.resultCh:
			m.lock.Lock()

			context, err := m.engine.GetDifficultyOrder(header)
			if err != nil {
				log.Println("Block mined has an invalid order")
			}

			if context == 0 {
				log.Println(color.Ize(color.Red, "PRIME block mined"))
				log.Println("PRIME:", header.Number, header.Hash())
			}

			if context == 1 {
				log.Println(color.Ize(color.Yellow, "REGION block mined"))
				log.Println("REGION:", header.Number, header.Hash())
			}

			if context == 2 {
				log.Println(color.Ize(color.Blue, "Zone block mined"))
				log.Println("ZONE:", header.Number, header.Hash())
			}

			// Check to see that all nodes are running before sending blocks to them.
			if !m.allChainsOnline() {
				log.Println("At least one of the chains is not online at the moment")
				continue
			}

			// Check proper difficulty for which nodes to send block to
			// Notify blocks to put in cache before assembling new block on node
			if context == 0 && header.Number[0] != nil {
				var wg sync.WaitGroup
				wg.Add(1)
				go m.SendMinedBlock(2, header, &wg)
				wg.Add(1)
				go m.SendMinedBlock(1, header, &wg)
				wg.Add(1)
				go m.SendMinedBlock(0, header, &wg)
				wg.Wait()
			}

			// If Region difficulty send to Region
			if context == 1 && header.Number[1] != nil {
				var wg sync.WaitGroup
				wg.Add(1)
				go m.SendMinedBlock(2, header, &wg)
				wg.Add(1)
				go m.SendMinedBlock(1, header, &wg)
				wg.Wait()
			}

			// If Zone difficulty send to Zone
			if context == 2 && header.Number[2] != nil {
				var wg sync.WaitGroup
				wg.Add(1)
				go m.SendMinedBlock(2, header, &wg)
				wg.Wait()
			}
			m.lock.Unlock()
		}
	}
}

// allChainsOnline checks if every single chain is online before sending the mined block to make sure that we don't have
// external blocks not found error
func (m *Manager) allChainsOnline() bool {
	if !checkConnection(m.orderedBlockClients.primeClient) {
		return false
	}
	for _, blockClient := range m.orderedBlockClients.regionClients {
		if !checkConnection(blockClient) {
			return false
		}
	}
	for i := range m.orderedBlockClients.zoneClients {
		for _, blockClient := range m.orderedBlockClients.zoneClients[i] {
			if !checkConnection(blockClient) {
				return false
			}
		}
	}
	return true
}

// SendMinedBlock sends the mined block to its mining client with the transactions, uncles, and receipts.
func (m *Manager) SendMinedBlock(mined int, header *types.Header, wg *sync.WaitGroup) {
	receiptBlock := m.pendingBlocks[mined]
	block := types.NewBlockWithHeader(receiptBlock.Header()).WithBody(receiptBlock.Transactions(), receiptBlock.Uncles())
	if block != nil {
		sealed := block.WithSeal(header)
		if mined == 0 {
			m.orderedBlockClients.primeClient.SendMinedBlock(context.Background(), sealed, true, true)
		}
		if mined == 1 {
			m.orderedBlockClients.regionClients[m.location[0]-1].SendMinedBlock(context.Background(), sealed, true, true)
		}
		if mined == 2 {
			m.orderedBlockClients.zoneClients[m.location[0]-1][m.location[1]-1].SendMinedBlock(context.Background(), sealed, true, true)
		}
	}
	defer wg.Done()
}

// Checks if a connection is still there on orderedBlockClient.chainAvailable
func checkConnection(client *ethclient.Client) bool {
	_, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Println("Error: connection lost")
		log.Println(err)
		return false
	} else {
		return true
	}
}

// Examines the Quai Network to find the Region-Zone location with lowest difficulty.
func findBestLocation(clients orderedBlockClients) []byte {
	lowestRegion := big.NewInt(math.MaxInt) // integer for holding lowest Region difficulty
	lowestZone := big.NewInt(math.MaxInt)   // integer for holding lowest Zone difficulty
	var regionLocation int                  // remember to return location as []byte with Zone1-1 = [1,1]
	var zoneLocation int

	// first find the Region chain with lowest difficulty
	for i, client := range clients.regionClients {
		latestHeader, err := client.HeaderByNumber(context.Background(), nil)
		if err != nil {
			log.Println("Error: connection lost during request")
			log.Println(err)
		} else {
			difficulty := latestHeader.Difficulty[1]
			if difficulty.Cmp(lowestRegion) == -1 {
				regionLocation = i + 1
				lowestRegion = difficulty
			}
			fmt.Println("region ", i+1, " difficulty ", difficulty)
		}
	}
	// next find Zone chain inside Region with lowest difficulty
	for i, client := range clients.zoneClients[regionLocation-1] {
		latestHeader, err := client.HeaderByNumber(context.Background(), nil)
		if err != nil {
			log.Println("Error: connect lost during request")
			log.Println(err)
		} else {
			difficulty := latestHeader.Difficulty[2]
			if difficulty.Cmp(lowestZone) == -1 {
				zoneLocation = i + 1
				lowestZone = difficulty
			}
			fmt.Println("zone ", i+1, " difficulty ", difficulty)
		}
	}

	// print location selected
	fmt.Println("Region location selected: ", regionLocation)
	fmt.Println("Zone location selected: ", zoneLocation)
	regionBytes := make([]byte, 8)
	zoneBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(regionBytes, uint64(regionLocation))
	binary.LittleEndian.PutUint64(zoneBytes, uint64(zoneLocation))
	// return location to config
	return []byte{regionBytes[0], zoneBytes[0]}
}

// Checks for best location to mine every 10 minutes;
// if better location is found it will initiate the change to the config.
func (m *Manager) checkBestLocation(timer int) {
	ticker := time.NewTicker(time.Duration(timer) * time.Minute)
	go func() {
		for {
			select {
			case <-exit:
				ticker.Stop()
				return
			case <-ticker.C:
				newLocation := findBestLocation(m.orderedBlockClients)
				// check if location has changed, and if true, update mining processes
				if !bytes.Equal(newLocation, m.location) {
					m.doneCh <- true // channel to make current processes stop
					m.location = newLocation
					m.doneCh <- false // set back to false to let new mining processes start
					m.subscribeAllPendingBlocks()
					m.fetchAllPendingBlocks()
				}
			}
		}
	}()
}

// Bundle of goroutines that need to be stopped and restarted if/when location updates.
func (m *Manager) subscribeAllPendingBlocks() {
	// subscribing to the pending blocks
	if m.orderedBlockClients.primeAvailable && checkConnection(m.orderedBlockClients.primeClient) {
		go m.subscribePendingHeader(m.orderedBlockClients.primeClient, 0)
	}
	if m.orderedBlockClients.regionsAvailable[m.location[0]-1] && checkConnection(m.orderedBlockClients.regionClients[m.location[0]-1]) {
		go m.subscribePendingHeader(m.orderedBlockClients.regionClients[m.location[0]-1], 1)
	}
	if m.orderedBlockClients.zonesAvailable[m.location[0]-1][m.location[1]-1] && checkConnection(m.orderedBlockClients.zoneClients[m.location[0]-1][m.location[1]-1]) {
		go m.subscribePendingHeader(m.orderedBlockClients.zoneClients[m.location[0]-1][m.location[1]-1], 2)
	}
}

// Bundle of goroutines that need to be stopped and restarted if/when location updates.
func (m *Manager) fetchAllPendingBlocks() {
	if m.orderedBlockClients.primeAvailable && checkConnection(m.orderedBlockClients.primeClient) {
		go m.fetchPendingBlocks(m.orderedBlockClients.primeClient, 0)
	}
	if m.orderedBlockClients.regionsAvailable[m.location[0]-1] && checkConnection(m.orderedBlockClients.regionClients[m.location[0]-1]) {
		go m.fetchPendingBlocks(m.orderedBlockClients.regionClients[m.location[0]-1], 1)
	}
	if m.orderedBlockClients.zonesAvailable[m.location[0]-1][m.location[1]-1] && checkConnection(m.orderedBlockClients.zoneClients[m.location[0]-1][m.location[1]-1]) {
		go m.fetchPendingBlocks(m.orderedBlockClients.zoneClients[m.location[0]-1][m.location[1]-1], 2)
	}
}
