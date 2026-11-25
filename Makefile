APP := quicbeam
PKG := ./cmd/quicbeam

.PHONY: build build-windows build-macos build-macos-amd64 build-android test tidy clean

build:
	CGO_ENABLED=0 go build -o bin/$(APP) $(PKG)

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/$(APP).exe $(PKG)

build-macos:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/$(APP)-darwin-arm64 $(PKG)

build-macos-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/$(APP)-darwin-amd64 $(PKG)

build-android:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/$(APP)-android-arm64 $(PKG)

test:
	go test -v -race ./...

tidy:
	go mod tidy

clean:
	rm -rf bin
