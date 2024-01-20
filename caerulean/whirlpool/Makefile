.ONESHELL:
.EXPORT_ALL_VARIABLES:

include example.conf.env

EXEC_NAME = whirlpool.run



build:
	@
	protoc -I=../../ --go_out=. ../../vessels/*.proto
	go mod tidy
	go build -o build/$(EXEC_NAME) ./sources
.PHONY: build

run: build
	@
	sudo build/$(EXEC_NAME)
.PHONY: run

format: build
	@
	go fmt ./sources
.PHONY: format



build-docker-prod:
	@
	DOCKER_BUILDKIT=1 docker build -f Dockerfile -t seaside-whirlpool-prod ../..
.PHONY: build-docker-prod

run-docker: build-docker-prod
	@
	docker run --privileged -it --rm --name seaside-whirlpool-run --env-file example.conf.env seaside-whirlpool-prod ../..
.PHONY: run-docker



build-docker-test:
	@
ifndef CI
	DOCKER_BUILDKIT=1 docker build -f Dockerfile.test -t seaside-whirlpool-test ../..
else
	DOCKER_BUILDKIT=1 docker build -f Dockerfile.test -t seaside-whirlpool-test -q ../..
endif
.PHONY: build-docker-test

lint: build-docker-test
	@
	docker run --privileged --rm --name seaside-whirlpool-lint --env-file example.conf.env --entrypoint golint seaside-whirlpool-test .
.PHONY: lint

test: build-docker-test
	@
	echo "Will be tested: $(shell docker run --rm --name seaside-whirlpool-test --env-file example.conf.env --entrypoint go seaside-whirlpool-test test ./tests  -list=.)"
ifndef CI
	docker run --privileged --rm --name seaside-whirlpool-test --env-file example.conf.env --entrypoint go seaside-whirlpool-test test -v ./tests
else
	docker run --privileged --rm --name seaside-whirlpool-test --env-file example.conf.env --entrypoint go seaside-whirlpool-test test ./tests
endif
.PHONY: test



clean:
	@
	rm -rf build
	rm -rf generated
	rm -f go.sum
	docker rm -f seaside-whirlpool-run seaside-whirlpool-lint seaside-whirlpool-test
	docker rmi -f seaside-whirlpool-prod seaside-whirlpool-test
.PHONY: clean
