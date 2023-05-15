test-caerulean-whirlpool:
	docker-compose -f test/docker-compose.yml up --force-recreate --build --abort-on-container-exit --exit-code-from vpnserver
.PHONY: test-caerulean-whirlpool

test-all: test-caerulean-whirlpool
.PHONY: test-all
