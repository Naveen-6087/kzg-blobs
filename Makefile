.PHONY: all build test bench lint fmt vet tidy clean

all: build test

build:
	go build -v ./...
	go build -v -o bin/kzgblobs ./cmd/kzgblobs

test:
	go test -v -race ./...

bench:
	go test ./kzg -run '^$$' -bench . -benchmem

lint: fmt vet
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/
