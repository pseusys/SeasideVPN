dependencies:
	go mod tidy
.PHONY: dependencies

build: dependencies
	go build -o build/main.run ./sources
.PHONY: build

save:
	iptables-save > ~/sysconfig.txt
.PHONY: save

run: build save
	sudo build/main.run -ip 127.0.0.1
.PHONY: run

restore:
	iptables-restore < ~/sysconfig.txt
.PHONY: restore

lint:
	golint .
	go fmt ./sources
.PHONY: lint

clean:
	rm -rf build
	rm -f go.sum
	rm -f ~/sysconfig.txt
.PHONY: clean
