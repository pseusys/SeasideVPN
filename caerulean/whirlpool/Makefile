.ONESHELL:
.EXPORT_ALL_VARIABLES:
.DEFAULT_GOAL := help

SHELL=/bin/bash
.SHELLFLAGS=-c -e

DOCKER_BUILDKIT = 1

BOLD=\033[1m
BLUE=\033[34m
GREEN=\033[32m
YELLOW=\033[33m
RESET=\033[0m

include example.conf.env

EXEC_NAME := whirlpool.run
PATH := $(PATH):$(shell go env GOPATH)/bin



help:
	@ # Print available make target information
	echo -e "$(BOLD)Available make targets$(RESET):"
	echo -e "\t$(BLUE)make build-docker-prod$(RESET): build Docker production image."
	echo -e "\t$(BLUE)make build-docker-test$(RESET): build Docker testing image."
	echo -e "\t$(BLUE)make build$(RESET): build whirlpool executable binary."
	echo -e "\t$(BLUE)make run$(RESET): run whirlpool executable locally."
	echo -e "\t$(BLUE)make run-docker$(RESET): run whirlpool executable in a Docker container."
	echo -e "\t$(BLUE)make test$(RESET): run tests in a Docker container."
	echo -e "\t$(BLUE)make lint$(RESET): run Go code linting in a Docker container."
	echo -e "\t$(BLUE)make format$(RESET): run Go code formatting locally."
	echo -e "\t$(BLUE)make clean$(RESET): clean all the build files, executables, Docker images, containers and networks."
	echo -e "\t$(BLUE)make help$(RESET): print this message again."
	echo -e "$(BOLD)Available environment variables$(RESET):"
	echo -e "\t$(GREEN)EXEC_NAME$(RESET): the name of the generated whirlpool executable."
	echo -e "\t$(YELLOW)example.conf.env$(RESET): contains environmental variables for executable running."
.PHONY: help



build:
	@ # Generate protobuf files, install dependencies and build executable
	protoc -I=../../ --go_out=. --go-grpc_out=. ../../vessels/*.proto
	go mod tidy
	go build -o build/$(EXEC_NAME) ./sources
.PHONY: build

run: build
	@ # Run executable
	if [ ! -d "certificates" ]; then
		${SHELL} whirlpool.sh -z
	fi
	sudo build/$(EXEC_NAME)
.PHONY: run

format: build
	@ # Format source files
	go fmt ./sources
.PHONY: format



build-docker-prod:
	@ # Build production Docker image
	docker build -f Dockerfile --target default -t seaside-whirlpool-prod ../..
.PHONY: build-docker-prod

run-docker: build-docker-prod
	@ # Run executable inside of the production Docker image
	docker run --privileged -it --rm --name seaside-whirlpool-run --env-file example.conf.env --network host seaside-whirlpool-prod ../..
.PHONY: run-docker



build-docker-test:
	@ # Build testing Docker image (verbose, if CI env var is not defined)
ifndef CI
	docker build -f Dockerfile --target builder -t seaside-whirlpool-test ../..
else
	docker build -f Dockerfile --target builder -t seaside-whirlpool-test -q ../..
endif
.PHONY: build-docker-test

lint: build-docker-test
	@ # Run lint inside of the testing docker container
	docker run --privileged --rm --name seaside-whirlpool-lint --env-file example.conf.env --entrypoint golint seaside-whirlpool-test .
.PHONY: lint

test: build-docker-test
	@ # Run tests inside of the testing docker container
ifndef CI
	docker run --privileged --rm --name seaside-whirlpool-test --env-file example.conf.env --entrypoint go seaside-whirlpool-test test -v ./...
else
	docker run --privileged --rm --name seaside-whirlpool-test --env-file example.conf.env --entrypoint go seaside-whirlpool-test test ./...
endif
.PHONY: test



clean:
	@ # Clean all the generated files, Docker images, containers and networks
	rm -rf build generated SeasideVPN
	rm -f go.sum conf.env
	docker rm -f seaside-whirlpool-run seaside-whirlpool-lint seaside-whirlpool-test
	docker rmi -f seaside-whirlpool-prod seaside-whirlpool-test
.PHONY: clean
