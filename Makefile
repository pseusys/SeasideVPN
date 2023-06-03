test-whirlpool:
	poetry -C viridian/algae install --all-extras
	poetry -C viridian/algae run test
.PHONY: test-whirlpool

test: test-whirlpool
.PHONY: test
