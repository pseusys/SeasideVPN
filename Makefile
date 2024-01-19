.ONESHELL:



install-algae:
	poetry -C viridian/algae install --without client,devel
.PHONY: install-algae

install-algae-all:
	poetry -C viridian/algae install
.PHONY: install-algae



test-whirlpool:
	make -C caerulean/whirlpool -s test
.PHONY: test-whirlpool

test-algae: install-algae
	poetry -C viridian/algae install --without client,devel
	poetry -C viridian/algae run test_all
.PHONY: test-algae

test: test-whirlpool test-algae
.PHONY: test



lint-whirlpool:
	make -C caerulean/whirlpool -s lint
.PHONY: lint-whirlpool

lint-algae: install-algae-all
	poetry -C viridian/algae run lint
.PHONY: lint-algae

lint: lint-whirlpool lint-algae
.PHONY: lint



clean-whirlpool:
	make -C caerulean/whirlpool -s clean
.PHONY: clean-whirlpool

clean-algae: install-algae
	poetry -C viridian/algae run clean
.PHONY: clean-algae

clean: clean-whirlpool clean-algae
.PHONY: clean
