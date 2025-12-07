############################
# Build Slider Client Only #
############################

# Set variables
BUILD_DIR := build

# UPX better compression by default
UPX_BRUTE ?= no

# Check if UPX is installed
UPX_CHECK := $(shell which upx 2>/dev/null)
ifdef UPX_CHECK
	UPX_AVAILABLE := yes
	# Strong compression if set
	ifeq ($(UPX_BRUTE), yes)
$(warning WARNING: Selected strong compression. This may take a while.)
		UPX_CMD := upx --best --lzma --brute
	else
		UPX_CMD := upx -9
	endif
else
	UPX_AVAILABLE := no
$(warning WARNING: UPX not found. Binaries will not be compressed. Install UPX for smaller binaries.)
endif

# Get OS information for platform-specific settings
UNAME_S := $(shell uname -s)

# Ensure build directory exists
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Default target
.PHONY: all
all: clean $(BUILD_DIR) macos-arm64-client macos-amd64-client windows-x86-client windows-amd64-client windows-arm64-client linux-x86-client linux-amd64-client linux-arm64-client

# Build for common platforms for quick testing
.PHONY: basic
basic: $(BUILD_DIR) macos-amd64-client linux-amd64-client windows-x86-client

# Build for arm64 platforms for quick testing
.PHONY: basic-arm64
basic-arm64: $(BUILD_DIR) macos-arm64-client linux-arm64-client windows-arm64-client

# Clean build directory
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)/*

# List all builds with their sizes
.PHONY: list
list:
	@echo "Available builds:"
	@ls -lh $(BUILD_DIR) | grep -v total

# macOS (arm64)
.PHONY: macos-arm64-client
macos-arm64-client:
	@echo "Building Client for macOS (arm64)..."
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/slider-client-darwin-arm64 main.go
	$(warning WARNING: UPX compression is not supported for macOS binaries.)

# macOS (amd64)
.PHONY: macos-amd64-client
macos-amd64-client:
	@echo "Building Client for macOS (amd64)..."
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/slider-client-darwin-amd64 main.go
	$(warning WARNING: UPX compression is not supported for macOS binaries.)

# Windows (x86)
.PHONY: windows-x86-client
windows-x86-client:
	@echo "Building Client for Windows (x86)..."
	GOOS=windows GOARCH=386 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/slider-client-windows-x86.exe main.go
ifeq ($(UPX_AVAILABLE),yes)
	@echo "Compressing with UPX..."
	$(UPX_CMD) $(BUILD_DIR)/slider-client-windows-x86.exe || echo "UPX compression failed, using uncompressed binary"
endif

# Windows (amd64)
.PHONY: windows-amd64-client
windows-amd64-client:
	@echo "Building Client for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/slider-client-windows-amd64.exe main.go
ifeq ($(UPX_AVAILABLE),yes)
	@echo "Compressing with UPX..."
	$(UPX_CMD) $(BUILD_DIR)/slider-client-windows-amd64.exe || echo "UPX compression failed, using uncompressed binary"
endif

# Windows (arm64)
.PHONY: windows-arm64-client
windows-arm64-client:
	@echo "Building Client for Windows (arm64)..."
	GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/slider-client-windows-arm64.exe main.go
	@echo "Note: UPX doesn't fully support Windows ARM64 binaries yet"

# Linux (x86)
.PHONY: linux-x86-client
linux-x86-client:
	@echo "Building Client for Linux (x86)..."
	GOOS=linux GOARCH=386 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/slider-client-linux-x86 main.go
ifeq ($(UPX_AVAILABLE),yes)
	@echo "Compressing with UPX..."
	$(UPX_CMD) $(BUILD_DIR)/slider-client-linux-x86 || echo "UPX compression failed, using uncompressed binary"
endif

# Linux (amd64)
.PHONY: linux-amd64-client
linux-amd64-client:
	@echo "Building Client for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/slider-client-linux-amd64 main.go
ifeq ($(UPX_AVAILABLE),yes)
	@echo "Compressing with UPX..."
	$(UPX_CMD) $(BUILD_DIR)/slider-client-linux-amd64 || echo "UPX compression failed, using uncompressed binary"
endif

# Linux (arm64)
.PHONY: linux-arm64-client
linux-arm64-client:
	@echo "Building Client for Linux (arm64)..."
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/slider-client-linux-arm64 main.go
ifeq ($(UPX_AVAILABLE),yes)
	@echo "Compressing with UPX..."
	$(UPX_CMD) $(BUILD_DIR)/slider-client-linux-arm64 || echo "UPX compression failed, using uncompressed binary"
endif