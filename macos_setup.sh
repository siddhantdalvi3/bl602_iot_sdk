#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting macOS environment setup for BL602 SDK...${NC}"

# 1. Check Homebrew
if ! command -v brew &> /dev/null; then
    echo -e "${RED}Homebrew not found. Please install Homebrew first: https://brew.sh/${NC}"
    exit 1
fi

# 2. Install Dependencies
echo -e "${GREEN}Installing dependencies via Homebrew...${NC}"
echo "Tapping riscv-software-src/riscv..."
brew tap riscv-software-src/riscv

echo "Installing riscv-tools, cmake, ninja, python3, dtc..."
brew install riscv-tools cmake ninja python3 dtc

# 3. Create and activate Python virtual environment
echo -e "${GREEN}Setting up Python virtual environment...${NC}"
VENV_DIR="venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists."
fi

# Activate the virtual environment
source "$VENV_DIR/bin/activate"
echo "Virtual environment activated."

# 4. Install Python Requirements
echo -e "${GREEN}Installing Python requirements...${NC}"
pip install --upgrade pip
pip install -r image_conf/requirements.txt

# 5. Patch project.mk for macOS RISC-V toolchain compatibility
# The standard RISC-V toolchain on macOS often requires rv32imafc instead of rv32imfc
echo -e "${GREEN}Patching make_scripts_riscv/project.mk for toolchain compatibility...${NC}"
PROJECT_MK="make_scripts_riscv/project.mk"
if [ -f "$PROJECT_MK" ]; then
    if grep -q "rv32imfc" "$PROJECT_MK"; then
        # Create backup
        cp "$PROJECT_MK" "$PROJECT_MK.bak"
        # Replace rv32imfc with rv32imafc
        sed -i '' 's/-march=rv32imfc/-march=rv32imafc/g' "$PROJECT_MK"
        echo "Successfully patched $PROJECT_MK"
    else
        echo "$PROJECT_MK already patched or does not contain rv32imfc."
    fi
else
    echo -e "${RED}Warning: $PROJECT_MK not found, skipping patch.${NC}"
fi

# 6. Install blflash
echo -e "${GREEN}Checking for blflash...${NC}"
if command -v blflash &> /dev/null; then
    echo "blflash is already installed."
else
    echo "Installing blflash via cargo..."

    # Check for cargo and install if missing
    if ! command -v cargo &> /dev/null; then
        echo "Cargo not found. Installing Rust via Homebrew..."
        brew install rust
    fi

    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}Cargo (Rust) not found. Please install Rust: https://rustup.rs/${NC}"
    else
        # Try installing from local tools if available (since we might have patched it)
        if [ -d "tools/blflash/blflash" ]; then
            echo "Installing from local tools/blflash/blflash..."
            cargo install --path tools/blflash/blflash
        else
            echo "Installing from crates.io..."
            cargo install blflash
        fi
    fi
fi

echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo "----------------------------------------------------------------"
echo "Please add the following lines to your ~/.zshrc or ~/.bash_profile:"
echo ""
echo "export BL60X_SDK_PATH=\"$(pwd)\""
echo "export CONFIG_CHIP_NAME=BL602"
echo "export CONFIG_TOOLPREFIX=riscv64-unknown-elf-"
echo ""
echo "After saving, run: source ~/.zshrc"
echo ""
echo -e "${GREEN}IMPORTANT:${NC} Before running 'make', always activate the virtual environment:"
echo ""
echo "  source $(pwd)/venv/bin/activate"
echo ""
echo "Have fun developing with the BL602 SDK!"
echo "----------------------------------------------------------------"
