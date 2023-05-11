dependencies:
	go mod tidy

build: dependencies
	go build -o build/main.run ./sources

save:
	iptables-restore < /etc/sysconfig.txt

run: build save
	sudo build/main.run -ip 127.0.0.1

restore:
	iptables-save > /etc/sysconfig.txt

lint:
	golint .
	go fmt ./sources

clean:
	rm -rf build
	rm -f go.sum
