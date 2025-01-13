#!/bin/bash
set -e

GREEN="\033[1;32m"
RED="\033[1;31m"
NC="\033[0m" # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Detect OS
OS=$(uname -s)
GO_VERSION_REQUIRED="1.22.3"
GO_VERSION_TARGET="1.23.4"

install_go_linux() {
    echo -e "⚙️  Installing Go $GO_VERSION_TARGET for Linux..."
    wget https://go.dev/dl/go${GO_VERSION_TARGET}.linux-amd64.tar.gz && \
    sudo rm -rf /usr/local/go && \
    sudo tar -C /usr/local -xzf go${GO_VERSION_TARGET}.linux-amd64.tar.gz && \
    rm go${GO_VERSION_TARGET}.linux-amd64.tar.gz && \
    export PATH=$PATH:/usr/local/go/bin && \
    print_success "Go $GO_VERSION_TARGET installed successfully." || print_error "Failed to install Go."
}

install_go_macos() {
    echo -e "⚙️  Installing Go $GO_VERSION_TARGET for macOS..."
    curl -LO https://go.dev/dl/go${GO_VERSION_TARGET}.darwin-amd64.pkg && \
    sudo installer -pkg go${GO_VERSION_TARGET}.darwin-amd64.pkg -target / && \
    rm go${GO_VERSION_TARGET}.darwin-amd64.pkg && \
    export PATH=$PATH:/usr/local/go/bin && \
    print_success "Go $GO_VERSION_TARGET installed successfully." || print_error "Failed to install Go."
}

check_go_version() {
    local version
    version=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ $(printf '%s\n' "$GO_VERSION_REQUIRED" "$version" | sort -V | head -n1) != "$GO_VERSION_REQUIRED" ]]; then
        print_error "Go version must be $GO_VERSION_REQUIRED or newer. Current version: $version"
    else
        print_success "Go version $version meets requirements."
    fi
}

install_go() {
    if [ "$OS" == "Linux" ]; then
        install_go_linux
    elif [ "$OS" == "Darwin" ]; then
        install_go_macos
    else
        print_error "Unsupported OS: $OS"
    fi
}

# Install Go if not present or outdated
if ! command -v go &> /dev/null; then
    echo -e "⚙️  Go not found. Installing Go $GO_VERSION_TARGET..."
    install_go
else
    echo -e "🔍 Checking Go version..."
    check_go_version
fi

# Install xcaddy if not present
if ! command -v xcaddy &> /dev/null; then
    echo -e "⚙️  xcaddy not found. Installing xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest && \
    export PATH=$PATH:$(go env GOPATH)/bin && \
    print_success "xcaddy installed successfully." || print_error "Failed to install xcaddy."
else
    print_success "xcaddy is already installed."
fi

# Clone the repository
if [ -d "caddy-waf" ]; then
    echo -e "🔄 caddy-waf directory already exists. Pulling latest changes..."
    cd caddy-waf && git pull || print_error "Failed to pull caddy-waf updates."
else
    echo -e "📥 Cloning caddy-waf repository..."
    git clone https://github.com/fabriziosalmi/caddy-waf.git && \
    cd caddy-waf && \
    print_success "caddy-waf repository cloned successfully." || print_error "Failed to clone repository."
fi

# Clean and update dependencies
echo -e "📦 Running go mod tidy..."
go mod tidy && print_success "Dependencies updated (go mod tidy)." || print_error "Failed to run go mod tidy."

echo -e "🔍 Fetching Go modules..."
go get -v github.com/caddyserver/caddy/v2 github.com/caddyserver/caddy/v2/caddyconfig/caddyfile github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile github.com/caddyserver/caddy/v2 github.com/caddyserver/caddy/v2/modules/caddyhttp github.com/oschwald/maxminddb-golang github.com/fsnotify/fsnotify github.com/fabriziosalmi/caddy-waf && \
print_success "Go modules fetched successfully." || print_error "Failed to fetch Go modules."
        
# Download GeoLite2 Country database
if [ ! -f "GeoLite2-Country.mmdb" ]; then
    echo -e "🌍 Downloading GeoLite2 Country database..."
    wget -q https://git.io/GeoLite2-Country.mmdb && \
    print_success "GeoLite2 database downloaded." || print_error "Failed to download GeoLite2 database."
else
    print_success "GeoLite2 database already exists."
fi

# Build with xcaddy
echo -e "⚙️  Building Caddy with caddy-waf module..."
xcaddy build --with github.com/fabriziosalmi/caddy-waf=./ && \
print_success "Caddy built successfully." || print_error "Failed to build Caddy."

# Format Caddyfile
echo -e "🧹 Formatting Caddyfile..."
./caddy fmt --overwrite && \
print_success "Caddyfile formatted." || print_error "Failed to format Caddyfile."

# Run Caddy
echo -e "🚀 Starting Caddy server..."
./caddy run && \
print_success "Caddy is running." || print_error "Failed to start Caddy."

