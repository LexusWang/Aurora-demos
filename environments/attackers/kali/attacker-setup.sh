#!/bin/bash
set -e

# ---------------------------------------------------------------
# Install location — self-contained so the script works whether
# invoked as `bash attacker-setup.sh`, `curl ... | bash`, or run
# from any working directory. Override with:
#   AURORA_EXECUTOR_HOME=/opt/aurora bash attacker-setup.sh
# ---------------------------------------------------------------
INSTALL_DIR="${AURORA_EXECUTOR_HOME:-$HOME/Aurora-executor}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
echo "[+] Installing Aurora attacker toolchain into: $INSTALL_DIR"

# Environment setup
VENV_NAME="env_aurora-executor"
CONFIG_FILE="config.ini"

# Install system dependencies
sudo apt-get update
sudo apt-get install -y virtualenv expect tmux wget

# Create Python virtual environment
virtualenv $VENV_NAME

# Install Python dependencies
$VENV_NAME/bin/pip install attack-executor==0.3.0 \
    questionary==2.1.0

# Download Sliver server
echo -e "\n[+] Downloading Sliver server..."
mkdir -p attack_tools
cd attack_tools
if [ ! -f "sliver-server_linux-amd64" ]; then
    wget https://github.com/BishopFox/sliver/releases/download/v1.7.2/sliver-server_linux-amd64
    chmod +x sliver-server_linux-amd64
    echo -e "[+] Sliver server downloaded successfully"
else
    echo -e "[*] Sliver server already exists, skipping download"
fi
cd ..

# Set default values without user interaction
# read -p "Path to Sliver client config [default: ~/zer0cool.cfg]: " sliver_path
# read -p "Metasploit RPC password [default: glycNshR]: " msf_pass
sliver_path="$PWD/zer0cool.cfg"
msf_pass="123456"

# Generate config file
cat > $CONFIG_FILE << EOF
[sliver]
client_config_file = $sliver_path

[metasploit]
password = $msf_pass
host_ip = 127.0.0.1
listening_port = 55552
EOF

# Kill existing tmux sessions (may not exist yet — don't abort on missing)
tmux kill-session -t msf 2>/dev/null || true
tmux kill-session -t sliver 2>/dev/null || true

# Check if msfconsole is available, install if not
if ! command -v msfconsole &> /dev/null; then
    echo -e "\n[!] Metasploit Framework not found. Installing..."
    sudo apt-get install -y metasploit-framework

    # Initialize Metasploit database
    echo -e "[+] Initializing Metasploit database..."
    sudo msfdb init

    # Verify installation
    if ! command -v msfconsole &> /dev/null; then
        echo -e "[!] ERROR: Failed to install Metasploit Framework"
        echo -e "[*] Skipping Metasploit RPC service..."
        MSF_AVAILABLE=false
    else
        echo -e "[+] Metasploit Framework installed successfully"
        MSF_AVAILABLE=true
    fi
else
    echo -e "\n[+] Metasploit Framework already installed"
    MSF_AVAILABLE=true
fi

# Start Metasploit RPC service if available
if [ "$MSF_AVAILABLE" = true ]; then
    echo -e "[+] Starting Metasploit RPC service..."
    tmux new-session -d -s msf \
      "msfconsole -q -x 'load msgrpc Pass=$msf_pass; setg MSGRPC_Pass $msf_pass; sleep 60000'"

    # Verify msf session was created
    sleep 2
    if ! tmux has-session -t msf 2>/dev/null; then
        echo -e "[!] WARNING: Failed to start Metasploit RPC session"
    else
        echo -e "[+] Metasploit RPC service started successfully"
    fi
fi

# Start Sliver C2 server
echo -e "[+] Starting Sliver C2 server..."
tmux new-session -d -s sliver \
  "./attack_tools/sliver-server_linux-amd64"

# Wait for server initialization
sleep 10

# Execute Sliver setup commands
echo -e "[+] Configuring Sliver server..."
tmux send-keys -t sliver "new-operator --name zer0cool --lhost localhost --lport 34567 --save $sliver_path -P all" Enter
sleep 3
tmux send-keys -t sliver "multiplayer --lport 34567" Enter


echo -e "\n[+] Deployment completed!"
echo -e "[*] Service management commands:"
echo -e "  View Metasploit session: tmux attach -t msf"
echo -e "  View Sliver session: tmux attach -t sliver"

# Instructions for activating virtual environment
echo -e "\n[!] To activate the virtual environment, run:"
echo -e "    source $VENV_NAME/bin/activate"
echo -e "\n[*] After activation, you can run attack scripts:"
echo -e "    python attack.py"
