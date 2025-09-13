#!/bin/bash

# Subfinder Installation Script for Ubuntu Linux
# This script installs Go (if needed) and subfinder from GitHub
set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
 
# Configuration
SUBFINDER_REPO=https://github.com/projectdiscovery/subfinder.git
INSTALL_DIR="/opt/bin"
GO_VERSION="1.21.5"  # Latest stable version as of script creation

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}
 
log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}


# Check if running as root for system-wide installation
check_permissions() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script needs to be run with sudo for system-wide installation"
        exit 1
    fi
  
    # Get the actual user who ran sudo
    ACTUAL_USER=${SUDO_USER:-$USER}
    ACTUAL_HOME=$(eval echo ~$ACTUAL_USER)
   
    log_info "Installing for user: $ACTUAL_USER"
    log_info "User home directory: $ACTUAL_HOME"
}

# Update system packages
update_system() {
    log_info "Updating system packages..."
    apt update -y
}

# Check if Go is installed and install if needed
check_and_install_go() {
    log_info "Checking for Go installation..."
   
    if command -v go >/dev/null 2>&1; then
        GO_CURRENT_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
        log_info "Go is already installed (version: $GO_CURRENT_VERSION)"
       
        # Check if version is recent enough (1.19+)
        if [ "$(printf '%s\n' "1.19" "$GO_CURRENT_VERSION" | sort -V | head -n1)" = "1.19" ]; then
            log_info "Go version is sufficient for subfinder"
            return 0
        else
            log_warn "Go version is too old, installing newer version..."
        fi
    else
        log_info "Go not found, installing..."
   fi
   
    # Install required packages
    apt install -y wget curl git
   
    # Download and install Go
    GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
    GO_URL=https://golang.org/dl/${GO_TARBALL}
   
    log_info "Downloading Go ${GO_VERSION}..."
    cd /tmp
    wget -q "$GO_URL"
   
    log_info "Installing Go..."
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$GO_TARBALL"
   
    # Clean up
    rm -f "$GO_TARBALL" 
    log_info "Go ${GO_VERSION} installed successfully"
}

 

# Create installation directory

create_install_dir() {
    log_info "Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
}
 
# Install subfinder using go install
install_subfinder() {
    log_info "Installing subfinder using go install..."
   
    # Set Go environment
    export PATH="/usr/local/go/bin:$PATH"
    export GOPATH="$ACTUAL_HOME/go"
    export GOBIN="$INSTALL_DIR"
  
    # Create GOPATH directories
    sudo -u "$ACTUAL_USER" mkdir -p "$ACTUAL_HOME/go/bin"
    sudo -u "$ACTUAL_USER" mkdir -p "$ACTUAL_HOME/go/pkg"
    sudo -u "$ACTUAL_USER" mkdir -p "$ACTUAL_HOME/go/src"
   
    # Try to install subfinder - test both possible paths
    log_info "Attempting to install subfinder..."
   
    # First try without v2 (newer structure)
    if GOBIN="$INSTALL_DIR" go install -v github.com/projectdiscovery/subfinder/cmd/subfinder@latest 2>/dev/null; then
        log_info "Successfully installed using path: github.com/projectdiscovery/subfinder/cmd/subfinder@latest"
    elif GOBIN="$INSTALL_DIR" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null; then
        log_info "Successfully installed using path: github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    else
        log_error "Failed to install subfinder using both possible paths"
        log_info "Trying alternative method: cloning and building manually..."
       
        # Fallback: clone and build manually
        cd /tmp
        rm -rf subfinder
        git clone "$SUBFINDER_REPO"
        cd subfinder
       
        # Find the correct subfinder directory
        if [ -d "cmd/subfinder" ]; then
            cd cmd/subfinder
            log_info "Building from cmd/subfinder directory"
        elif [ -d "v2/cmd/subfinder" ]; then
            cd v2/cmd/subfinder
            log_info "Building from v2/cmd/subfinder directory"
        else
            log_error "Cannot find subfinder source directory"
            exit 1
        fi
      
        # Build and install
        go build .
        cp subfinder "$INSTALL_DIR/"
       
        # Clean up
        cd /
        rm -rf /tmp/subfinder
       
        log_info "Subfinder built and installed manually"
    fi
   
    # Make sure binary is executable
    chmod +x "$INSTALL_DIR/subfinder"
   
    log_info "Subfinder installed successfully"
}

# Add /opt/bin to user's PATH
setup_user_path() {
    log_info "Setting up PATH for user $ACTUAL_USER..."
   
    USER_BASHRC="$ACTUAL_HOME/.bashrc"
    USER_PROFILE="$ACTUAL_HOME/.profile"
   
    # Check if /opt/bin is already in PATH
    if sudo -u "$ACTUAL_USER" bash -c 'echo $PATH' | grep -q "/opt/bin"; then
        log_info "/opt/bin is already in user's PATH"
        return 0
    fi
  
    # Add to .bashrc
    if [ -f "$USER_BASHRC" ]; then
        echo "" >> "$USER_BASHRC"
        echo "# Added by subfinder installer" >> "$USER_BASHRC"
        echo 'export PATH="/opt/bin:$PATH"' >> "$USER_BASHRC"
        log_info "Added /opt/bin to $USER_BASHRC"
    fi
   
    # Add to .profile as backup
    if [ -f "$USER_PROFILE" ]; then
       echo "" >> "$USER_PROFILE"
       echo "# Added by subfinder installer" >> "$USER_PROFILE"
       echo 'export PATH="/opt/bin:$PATH"' >> "$USER_PROFILE"
       log_info "Added /opt/bin to $USER_PROFILE"
    fi
   
    # Change ownership back to user
    chown "$ACTUAL_USER:$ACTUAL_USER" "$USER_BASHRC" 2>/dev/null || true
    chown "$ACTUAL_USER:$ACTUAL_USER" "$USER_PROFILE" 2>/dev/null || true
}
 
# Add Go to system PATH
setup_go_path() {
    log_info "Setting up Go PATH system-wide..."
   
    # Add Go to system PATH
    if ! grep -q "/usr/local/go/bin" /etc/environment; then
        # Backup current PATH from /etc/environment
        if [ -f /etc/environment ]; then
            CURRENT_PATH=$(grep '^PATH=' /etc/environment | cut -d= -f2 | tr -d '"')
            if [ -n "$CURRENT_PATH" ]; then
                sed -i 's|^PATH=.*|PATH="/usr/local/go/bin:'$CURRENT_PATH'"|' /etc/environment
            else
                echo 'PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' >> /etc/environment
            fi
        else
            echo 'PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' > /etc/environment
        fi
        log_info "Added Go to system PATH"
    fi
   
    # Also add to current session
    export PATH="/usr/local/go/bin:$PATH"
}
 
# Verify installation
verify_installation() {
    log_info "Verifying installation..."
   
   # Test subfinder
    if [ -x "$INSTALL_DIR/subfinder" ]; then
        log_info "Subfinder binary found at $INSTALL_DIR/subfinder"
       
        # Test with version flag
        SUBFINDER_VERSION=$("$INSTALL_DIR/subfinder" -version 2>/dev/null || echo "version check failed")
        log_info "Subfinder version: $SUBFINDER_VERSION"
    else
        log_error "Subfinder binary not found at $INSTALL_DIR/subfinder"
        exit 1
    fi
   
    # Test Go
    if /usr/local/go/bin/go version >/dev/null 2>&1; then
        GO_INSTALLED_VERSION=$(/usr/local/go/bin/go version | cut -d' ' -f3)
        log_info "Go version: $GO_INSTALLED_VERSION"
    else
        log_error "Go installation verification failed"
        exit 1
    fi
}
 
# Main installation process
main() {
    log_info "Starting Subfinder installation..."
    log_info "Repository: $SUBFINDER_REPO"
    log_info "Installation directory: $INSTALL_DIR"
   
    check_permissions
    update_system
    check_and_install_go
    setup_go_path
    create_install_dir
    install_subfinder
    setup_user_path
    verify_installation
    log_info "Installation completed successfully!"
    echo
    log_info "To use subfinder:"
    log_info "1. Log out and log back in (or run: source ~/.bashrc)"
    log_info "2. Run: subfinder -h"
    log_info "3. Or run directly: $INSTALL_DIR/subfinder -h"
    echo

    log_info "Note: For API integrations, configure ~/.config/subfinder/provider-config.yaml"
    log_info "Run 'subfinder -ls' to see available sources"
}
 
# Run main function
main "$@"
