test-caerulean-whirlpool:
	docker network prune -f
	docker-compose -f turquoise/no-check.yml up --force-recreate --build --abort-on-container-exit --exit-code-from vpnclient
	docker network prune -f
	docker-compose -f turquoise/tests.yml up --force-recreate --build --abort-on-container-exit --exit-code-from vpnclient
	docker network prune -f
.PHONY: test-caerulean-whirlpool

test-all: test-caerulean-whirlpool
.PHONY: test-all
