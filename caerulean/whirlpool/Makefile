.ONESHELL:

EXECUTABLE_NAME = whirlpool.run

build:
	go mod tidy
	protoc -I=../../ --go_out=. ../../vessels/*.proto
	go build -o build/$(EXECUTABLE_NAME) ./sources
.PHONY: build

run: build
	sudo build/$(EXECUTABLE_NAME) -ip 127.0.0.1
.PHONY: run

lint: build
	golint .
	go fmt ./sources
.PHONY: lint

test: build
ifndef CI
	go test -v ./tests
else
	go test ./tests
endif
.PHONY: test

clean:
	rm -rf build
	rm -f go.sum
	rm -f ~/sysconfig.txt
.PHONY: clean
