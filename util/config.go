package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/spf13/viper"
)

type JsonRequest struct {
	JsonRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Id      int    `json:"id"`
}

type JsonResponse struct {
	JsonRPC string `json:"jsonrpc"`
	Id      int    `json:"id"`
	Result  string `json:"result"`
}

type ResponseData struct {
	Error  string `json:"error"`
	Result string `json:"result"`
}

func lookupChainId(url string) (int64, error) {
	jsonData := JsonRequest{
		JsonRPC: "2.0",
		Method:  "eth_chainId",
		Id:      1,
	}

	jsonValue, _ := json.Marshal(jsonData)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonValue))

	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var jsonResponse JsonResponse

	json.Unmarshal(body, &jsonResponse)

	chainId, err := strconv.ParseInt(jsonResponse.Result[2:], 16, 64) // omit the "0x" prefix
	if err != nil {
		return 0, err
	}

	return chainId, nil
}

type Config struct {
	Ports   map[string]Zone
	ChainId int64
}

type Zone struct {
	Http int `mapstructure:"http"`
	Ws   int `mapstructure:"ws"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(host string) (config Config, err error) {
	networks := map[int64]string{
		1337:  "default",
		9000:  "colosseum",
		12000: "garden",
		15000: "orchard",
		17000: "galena",
	}

	viper.AddConfigPath("./config")
	viper.SetConfigName("default") // name of config file (without extension)
	viper.SetConfigType("yaml")    // REQUIRED if the config file does not have the extension in the name
	err = viper.ReadInConfig()     // Find and read the config file

	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %w \n", err))
	}

	err = viper.Unmarshal(&config)
	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %w \n", err))
	}

	chainId, err := lookupChainId(fmt.Sprintf("http://%s:%d", host, config.Ports["zone-0-0"].Http)) // add host as an input to this fn that comes from a flag
	if err != nil {                                                                                 // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error getting chainId: %w \n", err))
	}
	config.ChainId = chainId

	viper.SetConfigName(networks[chainId]) // name of config file (without extension)
	err = viper.MergeInConfig()            // Find and read the config file

	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %w \n", err))
	}

	err = viper.Unmarshal(&config)
	return
}
