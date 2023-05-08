dependencies:
	go mod tidy

build: dependencies
	go build -o build/main.run ./sources

run: build
	sudo build/main.run -local 127.0.0.3 -remote 127.0.0.5

lint:
	golint .
	go fmt ./sources

clean:
	rm -rf build
	rm -f go.sum
