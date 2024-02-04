.ONESHELL:
.EXPORT_ALL_VARIABLES:
.DEFAULT_GOAL := help

DOCKER_BUILDKIT = 1

include example.conf.env

EXEC_NAME = whirlpool.run



help:
	@ # Print available make target information
	echo "\033[1mAvailable make targets\033[0m:"
	echo "\t\033[34mmake build-docker-prod\033[0m: build Docker production image."
	echo "\t\033[34mmake build-docker-test\033[0m: build Docker testing image."
	echo "\t\033[34mmake build\033[0m: build whirlpool executable binary."
	echo "\t\033[34mmake run\033[0m: run whirlpool executable locally."
	echo "\t\033[34mmake run-docker\033[0m: run whirlpool executable in a Docker container."
	echo "\t\033[34mmake test\033[0m: run tests in a Docker container."
	echo "\t\033[34mmake lint\033[0m: run Go code linting in a Docker container."
	echo "\t\033[34mmake format\033[0m: run Go code formatting locally."
	echo "\t\033[34mmake clean\033[0m: clean all the build files, executables, Docker images, containers and networks."
	echo "\t\033[34mmake help\033[0m: print this message again."
	echo "\033[1mAvailable environment variables\033[0m:"
	echo "\t\033[32mEXEC_NAME\033[0m: the name of the generated whirlpool executable."
	echo "\t\033[33mexample.conf.env\033[0m: contains environmental variables for executable running."
.PHONY: help



build:
	@ # Generate protobuf files, install dependencies and build executable
	protoc -I=../../ --go_out=. ../../vessels/*.proto
	go mod tidy
	go build -o build/$(EXEC_NAME) ./sources
.PHONY: build

run: build
	@ # Run executable
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
	docker run --privileged -it --rm --name seaside-whirlpool-run --env-file example.conf.env seaside-whirlpool-prod ../..
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
	rm -rf build
	rm -rf generated
	rm -f go.sum
	docker rm -f seaside-whirlpool-run seaside-whirlpool-lint seaside-whirlpool-test
	docker rmi -f seaside-whirlpool-prod seaside-whirlpool-test
.PHONY: clean
