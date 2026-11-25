APP := quicbeam
PKG := ./cmd/quicbeam

.PHONY: build build-windows build-android test tidy clean

build:
	CGO_ENABLED=0 go build -o bin/$(APP) $(PKG)

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/$(APP).exe $(PKG)

build-android:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/$(APP)-android-arm64 $(PKG)

test:
	go test -v -race ./...

tidy:
	go mod tidy

clean:
	rm -rf bin
