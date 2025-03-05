# Makefile for Slider cross-platform build

# Set variables
BUILD_DIR := build

# Check if UPX is installed
UPX_CHECK := $(shell which upx 2>/dev/null)
ifdef UPX_CHECK
  UPX_AVAILABLE := yes
  UPX_CMD := upx -9
else
  UPX_AVAILABLE := no
  UPX_CMD := echo "UPX not installed, skipping compression for"
endif

# Get OS information for platform-specific settings
UNAME_S := $(shell uname -s)

# Ensure build directory exists
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Default target
.PHONY: all
all: clean $(BUILD_DIR) macos-arm64 macos-amd64 windows-x86 windows-amd64 windows-arm64 linux-x86 linux-amd64

# Clean build directory
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)/*

# macOS (arm64)
.PHONY: macos-arm64
macos-arm64:
	@echo "Building for macOS (arm64)..."
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/slider-darwin-arm64 main.go
	@echo "Note: UPX compression is not supported for macOS binaries"

# macOS (amd64)
.PHONY: macos-amd64
macos-amd64:
	@echo "Building for macOS (amd64)..."
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/slider-darwin-amd64 main.go
	@echo "Note: UPX compression is not supported for macOS binaries"

# Windows (x86)
.PHONY: windows-x86
windows-x86:
	@echo "Building for Windows (x86)..."
	GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o $(BUILD_DIR)/slider-windows-x86.exe main.go
ifeq ($(UPX_AVAILABLE),yes)
	@echo "Compressing with UPX..."
	$(UPX_CMD) $(BUILD_DIR)/slider-windows-x86.exe || echo "UPX compression failed, using uncompressed binary"
endif

# Windows (amd64)
.PHONY: windows-amd64
windows-amd64:
	@echo "Building for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/slider-windows-amd64.exe main.go
ifeq ($(UPX_AVAILABLE),yes)
	@echo "Compressing with UPX..."
	$(UPX_CMD) $(BUILD_DIR)/slider-windows-amd64.exe || echo "UPX compression failed, using uncompressed binary"
endif

# Windows (arm64)
.PHONY: windows-arm64
windows-arm64:
	@echo "Building for Windows (arm64)..."
	GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/slider-windows-arm64.exe main.go
	@echo "Note: UPX doesn't fully support Windows ARM64 binaries yet"

# Linux (x86)
.PHONY: linux-x86
linux-x86:
	@echo "Building for Linux (x86)..."
	GOOS=linux GOARCH=386 go build -ldflags="-s -w" -o $(BUILD_DIR)/slider-linux-x86 main.go
ifeq ($(UPX_AVAILABLE),yes)
	@echo "Compressing with UPX..."
	$(UPX_CMD) $(BUILD_DIR)/slider-linux-x86 || echo "UPX compression failed, using uncompressed binary"
endif

# Linux (amd64)
.PHONY: linux-amd64
linux-amd64:
	@echo "Building for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/slider-linux-amd64 main.go
ifeq ($(UPX_AVAILABLE),yes)
	@echo "Compressing with UPX..."
	$(UPX_CMD) $(BUILD_DIR)/slider-linux-amd64 || echo "UPX compression failed, using uncompressed binary"
endif

# List all builds with their sizes
.PHONY: list
list:
	@echo "Available builds:"
	@ls -lh $(BUILD_DIR) | grep -v total
