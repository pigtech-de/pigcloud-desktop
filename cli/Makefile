VERSION ?= 1.0.0
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

DIST := dist

.PHONY: all clean build build-all test install sync-filetypes

all: build

sync-filetypes:
	@true

build: sync-filetypes
	go build $(LDFLAGS) -o $(DIST)/pigcloud .
	@cp $(DIST)/pigcloud $(DIST)/pc 2>/dev/null || copy $(DIST)\\pigcloud $(DIST)\\pc 2>nul

build-all: clean sync-filetypes
	@mkdir -p $(DIST) 2>/dev/null || mkdir $(DIST) 2>nul

	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/pigcloud-linux-amd64 .
	@cp $(DIST)/pigcloud-linux-amd64 $(DIST)/pc-linux-amd64

	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/pigcloud-linux-arm64 .
	@cp $(DIST)/pigcloud-linux-arm64 $(DIST)/pc-linux-arm64

	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/pigcloud-darwin-amd64 .
	@cp $(DIST)/pigcloud-darwin-amd64 $(DIST)/pc-darwin-amd64

	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/pigcloud-darwin-arm64 .
	@cp $(DIST)/pigcloud-darwin-arm64 $(DIST)/pc-darwin-arm64

	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/pigcloud-windows-amd64.exe .
	@cp $(DIST)/pigcloud-windows-amd64.exe $(DIST)/pc-windows-amd64.exe

	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/pigcloud-windows-arm64.exe .
	@cp $(DIST)/pigcloud-windows-arm64.exe $(DIST)/pc-windows-arm64.exe

	@echo "Build complete! Binaries in $(DIST)/"

build-windows: sync-filetypes
	@if not exist $(DIST) mkdir $(DIST)
	go build $(LDFLAGS) -o $(DIST)/pigcloud.exe .
	@copy $(DIST)\\pigcloud.exe $(DIST)\\pc.exe >nul 2>&1

install:
	go install $(LDFLAGS) .

test:
	go test -v ./...

deps:
	go mod download
	go mod tidy

clean:
	@rm -rf $(DIST) 2>/dev/null || rmdir /s /q $(DIST) 2>nul || echo "Clean"

checksums:
	@cd $(DIST) && sha256sum pigcloud-* pc-* 2>/dev/null > checksums.txt || \
		(for %%f in (pigcloud-* pc-*) do @certutil -hashfile %%f SHA256 >> checksums.txt 2>nul)

release: build-all
	@echo "Creating release archives..."
	@cd $(DIST) && for plat in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do \
		rm -rf stage && mkdir stage && \
		install -m 755 pigcloud-$$plat stage/pigcloud && install -m 755 pc-$$plat stage/pc && \
		tar -czf pigcloud-$(VERSION)-$$plat.tar.gz -C stage pigcloud pc \
		|| echo "Skipping $$plat archive"; done
	@cd $(DIST) && for plat in windows-amd64 windows-arm64; do \
		rm -rf stage && mkdir stage && \
		install -m 755 pigcloud-$$plat.exe stage/pigcloud.exe && install -m 755 pc-$$plat.exe stage/pc.exe && \
		(cd stage && zip -q ../pigcloud-$(VERSION)-$$plat.zip pigcloud.exe pc.exe) \
		|| echo "Skipping $$plat archive"; done
	@cd $(DIST) && rm -rf stage && sha256sum *.tar.gz *.zip 2>/dev/null > checksums.txt || echo "Checksums generated"
	@echo "Release archives created in $(DIST)/"

help:
	@echo "PigCloud CLI Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make build         - Build for current platform"
	@echo "  make build-all     - Build for all platforms"
	@echo "  make build-windows - Build for Windows (dev)"
	@echo "  make release       - Build all + create archives + checksums"
	@echo "  make install       - Install to GOPATH/bin"
	@echo "  make test          - Run tests"
	@echo "  make deps          - Download dependencies"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make checksums     - Generate SHA256 checksums"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION)  (override with: make VERSION=1.2.3)"
	@echo "  COMMIT=$(COMMIT)"
