test-whirlpool:
	make -C caerulean/whirlpool -s test
.PHONY: test-whirlpool

test-algae:
	poetry -C viridian/algae install --without client,devel
	poetry -C viridian/algae run test_all
.PHONY: test-algae

test: test-whirlpool test-algae
.PHONY: test



lint-whirlpool:
	make -C caerulean/whirlpool --no-print-directory lint
.PHONY: lint-whirlpool

lint-algae:
	poetry -C viridian/algae install --without client,devel
	poetry -C viridian/algae run lint
.PHONY: lint-algae

lint: lint-whirlpool lint-algae
.PHONY: lint
