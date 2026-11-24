APP := quicbeam
PKG := ./cmd/quicbeam

.PHONY: build build-windows test tidy clean

build:
	CGO_ENABLED=0 go build -o bin/$(APP) $(PKG)

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/$(APP).exe $(PKG)

test:
	go test -v ./...

tidy:
	go mod tidy

clean:
	rm -rf bin
