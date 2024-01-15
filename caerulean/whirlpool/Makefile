.ONESHELL:
.EXPORT_ALL_VARIABLES:

include example.conf.env

EXECUTABLE_NAME = whirlpool.run

build:
	protoc -I=../../ --go_out=. ../../vessels/*.proto
	go mod tidy
	go build -o build/$(EXECUTABLE_NAME) ./sources
.PHONY: build

build-docker:
	docker build -f Dockerfile -t "seaside-whirlpool-latest" ../..
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
	rm -rf generated
	rm -f go.sum
	docker rmi --force "seaside-whirlpool-latest"
.PHONY: clean
