test-algae:
	poetry -C viridian/algae install --all-extras
	poetry -C viridian/algae run test
.PHONY: test-algae

test: test-algae
.PHONY: test



lint-whirlpool:
	make -C caerulean/whirlpool --no-print-directory lint
.PHONY: lint-whirlpool

lint-algae:
	poetry -C viridian/algae install --all-extras
	poetry -C viridian/algae run lint
.PHONY: lint-algae

lint: lint-whirlpool lint-algae
.PHONY: lint
