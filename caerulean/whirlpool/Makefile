.ONESHELL:
.EXPORT_ALL_VARIABLES:

include example.conf.env

EXECUTABLE_NAME = whirlpool.run



generate:
	protoc -I=../../ --go_out=. ../../vessels/*.proto
.PHONY: generate

build: generate
	go mod tidy
	go build -o build/$(EXECUTABLE_NAME) ./sources
.PHONY: build

run: build
	sudo build/$(EXECUTABLE_NAME)
.PHONY: run

format: build
	go fmt ./sources
.PHONY: format



build-docker-prod:
	docker build -f Dockerfile.prod -t seaside-whirlpool-prod ../..
.PHONY: build-docker-prod

run-docker: build-docker-prod
	docker run -it --rm --name seaside-whirlpool-run seaside-whirlpool-prod
.PHONY: run-docker



build-docker-test: generate
ifndef CI
	docker build -f Dockerfile.test -t seaside-whirlpool-test .
else
	docker build -f Dockerfile.test -t seaside-whirlpool-test -q .
endif
.PHONY: build-docker-test

lint: build-docker-test
	docker run --rm --name seaside-whirlpool-lint --env-file example.conf.env --entrypoint golint seaside-whirlpool-test .
.PHONY: lint

test: build-docker-test
ifndef CI
	docker run --rm --name seaside-whirlpool-test --env-file example.conf.env --entrypoint go seaside-whirlpool-test test -v ./tests
else
	docker run --rm --name seaside-whirlpool-test --env-file example.conf.env --entrypoint go seaside-whirlpool-test test ./tests
endif
.PHONY: test



clean:
	rm -rf build
	rm -rf generated
	rm -f go.sum
	docker rm -f seaside-whirlpool-run seaside-whirlpool-lint seaside-whirlpool-test
	docker rmi -f seaside-whirlpool-prod seaside-whirlpool-test
.PHONY: clean
