# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

GOBIN = ./build/bin
GO ?= latest
GORUN = env GO111MODULE=on go run

tx-spammer:
	go build -o ./build/bin/tx-spammer spammer/main.go  
	@echo "Done building."
	@echo "Run \"$(GOBIN)/tx-spammer\" to launch tx-spammer"

run:
	./build/bin/tx-spammer $(group) $(host)

run-background:
	./build/bin/tx-spammer $(group) 2>&1 &

stop:
ifeq ($(shell uname -s),Darwin)
	@if pgrep tx-spammer; then pkill -f ./build/bin/tx-spammer; fi
	@while pgrep tx-spammer >/dev/null; do \
		echo "Stopping all Quai TX Spammers, please wait until terminated."; \
		sleep 3; \
	done;
else
	@echo "Stopping all Quai TX Spammers, please wait until terminated.";
	@if pgrep tx-spammer; then killall -w ./build/bin/tx-spammer; fi
endif
