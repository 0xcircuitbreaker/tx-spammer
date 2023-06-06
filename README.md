# External Token Transfer test vector

This fork of the transactor adds a test vector that deploys an ERC20X contract on two chains, approves them on each chain, and sends a token from one chain to the other.

## Building the source

Build via Makefile

```shell
make
```

## Run
```shell
make run group=0
```

NOTE: You must run a node and mine in at least cyprus 1 and cyprus 2.
Change params at the top of spammer/main.go for the correct network.

## What the test vector does
The test vector contained in this fork of the transactor begins by deploying ERC20X.sol in cyprus 1 and cyprus 2 using the bytecode (compiled) representation of the smart contract. After the contracts are deployed, the script deploys a transaction that adds the address in cyprus 1 as an approved minting contract in cyprus 2, and sends another transaction that adds the address in cyprus 2 as an approved minting contract in cyprus 1. The script then calls the crossChainTransfer() function on the contract in cyprus 1 and sends a transaction with the proper payload to call this function. The function constructs an ETX that tells the contract in cyprus 2 to mint a token to an address in cyprus 2. The script waits 60 seconds for the ETX to be played (1 zone block and 1 region block in cyprus 1 plus 1 region block and 1 zone block in cyprus 2). After 60 seconds the script checks the balance of the address in cyprus 2 and the balance of the address in cyprus 1.