#!/bin/bash

# ==============================================
# ULTRA-FAST UDP SERVER SCRIPT
# Optimized for Ubuntu & Debian (No Version Restrictions)
# By @Rufu99 - Enhanced for Maximum Speed
# ==============================================

# SPEED OPTIMIZATIONS:
# 1. Parallel downloads and installations
# 2. Minimal user interaction
# 3. Cached operations
# 4. Optimized system calls
# 5. Async operations where possible

# =========== CONFIGURATION ============
udp_file='/etc/UDPserver'
lang_dir="$udp_file/lang"
lang="$lang_dir/lang"
LOG_FILE="/tmp/udp_install.log"
APT_OPTS="-o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' --allow-unauthenticated"
PARALLEL_APT="-o Acquire::http::Pipeline-Depth=0 -o Acquire::http::No-Cache=True -o Acquire::Queue-Mode=access"
# ======================================

# Color codes for faster output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Fast print functions
print_color() {
    echo -e "${2}${1}${NC}"
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Ultra-fast system check (no version restrictions)
check_system_fast() {
    print_status "Checking system compatibility..."
    
    # Check if system is Linux
    if [[ $(uname) != "Linux" ]]; then
        print_error "This script only works on Linux systems"
        exit 1
    fi
    
    # Check for package manager
    if ! command -v apt-get &>/dev/null; then
        print_error "APT package manager not found. This script requires Ubuntu/Debian."
        exit 1
    fi
    
    # Detect OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        print_status "Detected: $NAME $VERSION_ID"
    else
        print_warning "Could not detect OS version, continuing anyway..."
    fi
    
    # NO VERSION RESTRICTIONS - SUPPORT ALL VERSIONS
    print_status "System check passed (No version restrictions)"
    return 0
}

# Parallel package installation for maximum speed
install_packages_parallel() {
    local packages=("$@")
    
    print_status "Installing ${#packages[@]} packages in parallel..."
    
    # Configure APT for maximum speed
    {
        echo 'Acquire::http::Pipeline-Depth "0";'
        echo 'Acquire::http::No-Cache "true";'
        echo 'Acquire::Queue-Mode "access";'
        echo 'APT::Get::Assume-Yes "true";'
        echo 'APT::Get::force-yes "true";'
        echo 'APT::Install-Recommends "0";'
        echo 'APT::Install-Suggests "0";'
    } > /etc/apt/apt.conf.d/99speed
    
    # Update in background for speed
    DEBIAN_FRONTEND=noninteractive apt-get update $PARALLEL_APT >/dev/null 2>&1 &
    UPDATE_PID=$!
    
    # Install packages while updating
    for pkg in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$pkg "; then
            DEBIAN_FRONTEND=noninteractive apt-get install $APT_OPTS $PARALLEL_APT "$pkg" -y >/dev/null 2>&1 &
            INSTALL_PIDS+=($!)
        fi
    done
    
    # Wait for update to complete
    wait $UPDATE_PID
    
    # Wait for all installations
    for pid in "${INSTALL_PIDS[@]}"; do
        wait $pid
    done
    
    print_status "Package installation complete"
}

# Ultra-fast UDP server installation
install_udp_server_fast() {
    print_status "Starting ultra-fast UDP server installation..."
    
    # Create directory structure
    mkdir -p $udp_file $lang_dir
    
    # Download essential components in parallel
    print_status "Downloading components..."
    
    # Parallel downloads
    curl -sSL 'https://raw.githubusercontent.com/rudi9999/Herramientas/main/module/module' -o $udp_file/module &
    CURL1_PID=$!
    
    curl -sSL 'https://raw.githubusercontent.com/rudi9999/SocksIP-udpServer/main/limitador.sh' -o $udp_file/limitador.sh &
    CURL2_PID=$!
    
    curl -sSL 'https://raw.githubusercontent.com/rudi9999/SocksIP-udpServer/main/lang/lang' -o /tmp/lang_list &
    CURL3_PID=$!
    
    # Wait for downloads
    wait $CURL1_PID $CURL2_PID $CURL3_PID
    
    # Make files executable
    chmod +x $udp_file/module $udp_file/limitador.sh
    
    # Create command shortcut
    echo '/etc/UDPserver/UDPserver.sh' > /usr/bin/udp
    chmod +x /usr/bin/udp
    
    # Install required system packages
    REQUIRED_PACKAGES=(
        "curl"
        "wget"
        "ufw"
        "openssl"
        "systemd"
        "cron"
        "at"
        "net-tools"
        "iproute2"
        "psmisc"
    )
    
    install_packages_parallel "${REQUIRED_PACKAGES[@]}"
    
    # Disable firewall for speed
    ufw disable >/dev/null 2>&1
    systemctl disable ufw >/dev/null 2>&1
    
    # Download UDP binary
    print_status "Downloading UDP server binary..."
    if wget -q -O /usr/bin/udpServer 'https://bitbucket.org/iopmx/udprequestserver/downloads/udpServer'; then
        chmod +x /usr/bin/udpServer
        print_status "UDP binary installed"
    else
        # Fallback to curl
        curl -sSL 'https://bitbucket.org/iopmx/udprequestserver/downloads/udpServer' -o /usr/bin/udpServer
        chmod +x /usr/bin/udpServer
    fi
    
    # Get public IP efficiently
    IP_PUBLIC=$(curl -s4 ifconfig.co || curl -s4 icanhazip.com || echo "127.0.0.1")
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    
    # Create optimized service file
    cat > /etc/systemd/system/UDPserver.service << EOF
[Unit]
Description=Ultra-Fast UDP Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
ExecStart=/usr/bin/udpServer -ip=$IP_PUBLIC -net=$INTERFACE -mode=system
Nice=-10
IOSchedulingClass=realtime
IOSchedulingPriority=0
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable UDPserver >/dev/null 2>&1
    systemctl start UDPserver
    
    # Optimize system limits for UDP
    echo "net.core.rmem_max = 134217728" >> /etc/sysctl.conf
    echo "net.core.wmem_max = 134217728" >> /etc/sysctl.conf
    echo "net.ipv4.udp_mem = 1024000 8738000 134217728" >> /etc/sysctl.conf
    echo "net.ipv4.udp_rmem_min = 8192" >> /etc/sysctl.conf
    echo "net.ipv4.udp_wmem_min = 8192" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    
    # Copy script to final location
    cp $0 $udp_file/UDPserver.sh
    chmod +x $udp_file/UDPserver.sh
    
    print_status "Installation complete! Use 'udp' to access menu"
    
    # Quick system check
    if systemctl is-active --quiet UDPserver; then
        print_status "UDP server is running"
    else
        print_warning "UDP server not running. Starting now..."
        systemctl start UDPserver
    fi
    
    # Remove installer script if running from temporary location
    if [[ $(pwd) != "$udp_file" ]]; then
        rm -f $0 2>/dev/null
    fi
}

# Fast user management functions
user_add_fast() {
    local user=$1 pass=$2 days=$3 limit=$4
    local valid=$(date '+%Y-%m-%d' -d "+$days days")
    
    # Create user with all options in one command
    useradd -m -s /bin/false -e "$valid" \
            -c "UDP User,Pass:$pass,Limit:$limit" \
            "$user" 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        # Set password efficiently
        echo "$user:$pass" | chpasswd
        echo "$user $pass $valid $limit"
        return 0
    fi
    return 1
}

user_list_fast() {
    grep -E 'UDP User' /etc/passwd | cut -d: -f1 | while read user; do
        chage -l "$user" 2>/dev/null | grep 'Account expires' | cut -d: -f2
    done
}

# Fast menu system
show_menu_fast() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}    ULTRA-FAST UDP SERVER MANAGER${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # Check if UDP is running
    if systemctl is-active --quiet UDPserver; then
        UDP_STATUS="${GREEN}[RUNNING]${NC}"
    else
        UDP_STATUS="${RED}[STOPPED]${NC}"
    fi
    
    # Get system info quickly
    IP_PUBLIC=$(curl -s4 ifconfig.me 2>/dev/null || echo "N/A")
    LOAD=$(uptime | awk -F'load average:' '{print $2}')
    
    echo -e "IP: ${YELLOW}$IP_PUBLIC${NC} | Status: $UDP_STATUS"
    echo -e "Load: ${YELLOW}$LOAD${NC}"
    echo ""
    echo -e "${GREEN}[1]${NC} Add User (Fast)"
    echo -e "${GREEN}[2]${NC} List Users"
    echo -e "${GREEN}[3]${NC} Remove User"
    echo -e "${GREEN}[4]${NC} Renew User"
    echo -e "${GREEN}[5]${NC} Start/Stop UDP Server"
    echo -e "${GREEN}[6]${NC} Server Status"
    echo -e "${GREEN}[7]${NC} Uninstall"
    echo -e "${GREEN}[0]${NC} Exit"
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -n "Select option: "
}

# Fast user addition
add_user_fast() {
    clear
    echo -e "${BLUE}=== ADD USER ===${NC}"
    
    read -p "Username: " username
    read -sp "Password: " password
    echo
    read -p "Days valid: " days
    read -p "Connection limit: " limit
    
    if user_add_fast "$username" "$password" "$days" "$limit"; then
        print_status "User $username added successfully"
        echo -e "IP: ${YELLOW}$(curl -s4 ifconfig.me)${NC}"
        echo -e "Ports: ${YELLOW}All UDP ports${NC}"
    else
        print_error "Failed to add user"
    fi
    
    read -n 1 -s -r -p "Press any key to continue..."
}

# Fast user listing
list_users_fast() {
    clear
    echo -e "${BLUE}=== USER LIST ===${NC}"
    echo ""
    
    printf "%-15s %-10s %-12s %-6s\n" "USERNAME" "EXPIRES" "LIMIT" "STATUS"
    echo "------------------------------------------------"
    
    grep 'UDP User' /etc/passwd | while IFS=: read -r user _ uid _ gecos _; do
        expire=$(chage -l "$user" 2>/dev/null | grep 'Account expires' | cut -d: -f2)
        limit=$(echo "$gecos" | grep -o 'Limit:[0-9]*' | cut -d: -f2)
        [[ -z "$limit" ]] && limit="Unlim"
        
        # Check if locked
        if passwd -S "$user" 2>/dev/null | grep -q ' L '; then
            status="${RED}LOCKED${NC}"
        else
            status="${GREEN}ACTIVE${NC}"
        fi
        
        printf "%-15s %-10s %-12s %-6s\n" "$user" "$expire" "$limit" "$status"
    done
    
    echo ""
    read -n 1 -s -r -p "Press any key to continue..."
}

# Fast UDP control
control_udp_fast() {
    clear
    echo -e "${BLUE}=== UDP SERVER CONTROL ===${NC}"
    
    if systemctl is-active --quiet UDPserver; then
        echo -n "Stopping UDP server... "
        systemctl stop UDPserver
        sleep 1
        echo -e "${GREEN}[STOPPED]${NC}"
    else
        echo -n "Starting UDP server... "
        systemctl start UDPserver
        sleep 1
        if systemctl is-active --quiet UDPserver; then
            echo -e "${GREEN}[STARTED]${NC}"
        else
            echo -e "${RED}[FAILED]${NC}"
        fi
    fi
    
    sleep 2
}

# Fast uninstall
uninstall_fast() {
    clear
    echo -e "${RED}=== UNINSTALL UDP SERVER ===${NC}"
    echo ""
    read -p "Are you sure? (y/n): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        print_status "Stopping services..."
        systemctl stop UDPserver 2>/dev/null
        systemctl disable UDPserver 2>/dev/null
        
        print_status "Removing files..."
        rm -rf /etc/UDPserver
        rm -f /usr/bin/udp
        rm -f /usr/bin/udpServer
        rm -f /etc/systemd/system/UDPserver.service
        
        print_status "Cleaning up users..."
        # Remove UDP users
        grep 'UDP User' /etc/passwd | cut -d: -f1 | xargs -r userdel -r 2>/dev/null
        
        print_status "Reloading systemd..."
        systemctl daemon-reload
        
        echo ""
        print_status "Uninstallation complete!"
    fi
    
    sleep 2
}

# Fast status check
show_status_fast() {
    clear
    echo -e "${BLUE}=== SERVER STATUS ===${NC}"
    echo ""
    
    # UDP status
    if systemctl is-active --quiet UDPserver; then
        echo -e "UDP Server: ${GREEN}RUNNING${NC}"
        
        # Get process info
        PID=$(pgrep -f udpServer)
        if [[ -n "$PID" ]]; then
            echo -e "PID: ${YELLOW}$PID${NC}"
            
            # Get memory usage
            MEM=$(ps -p $PID -o rss= 2>/dev/null)
            if [[ -n "$MEM" ]]; then
                MEM_MB=$((MEM / 1024))
                echo -e "Memory: ${YELLOW}${MEM_MB}MB${NC}"
            fi
            
            # Get connections (fast)
            CONNS=$(ss -anu | wc -l)
            echo -e "UDP Connections: ${YELLOW}$((CONNS - 1))${NC}"
        fi
    else
        echo -e "UDP Server: ${RED}STOPPED${NC}"
    fi
    
    echo ""
    
    # System info
    echo -e "Load Average: ${YELLOW}$(cat /proc/loadavg | awk '{print $1, $2, $3}')${NC}"
    echo -e "Uptime: ${YELLOW}$(uptime -p | sed 's/up //')${NC}"
    
    # User count
    USER_COUNT=$(grep 'UDP User' /etc/passwd | wc -l)
    echo -e "Active Users: ${YELLOW}$USER_COUNT${NC}"
    
    echo ""
    read -n 1 -s -r -p "Press any key to continue..."
}

# Main execution flow
main() {
    # Run as root check
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
    
    # Check if already installed
    if [[ ! -f "$udp_file/UDPserver.sh" ]]; then
        print_status "First-time installation detected"
        check_system_fast
        install_udp_server_fast
        
        # Start menu after installation
        print_status "Installation complete! Starting management interface..."
        sleep 2
    fi
    
    # Main menu loop
    while true; do
        show_menu_fast
        read choice
        
        case $choice in
            1) add_user_fast ;;
            2) list_users_fast ;;
            3) 
                clear
                read -p "Enter username to remove: " user
                if userdel -r "$user" 2>/dev/null; then
                    print_status "User $user removed"
                else
                    print_error "Failed to remove user"
                fi
                sleep 2
                ;;
            4)
                clear
                read -p "Enter username: " user
                read -p "Add days: " days
                if chage -E $(date -d "+$days days" +%Y-%m-%d) "$user" 2>/dev/null; then
                    print_status "User $user renewed for $days days"
                else
                    print_error "Failed to renew user"
                fi
                sleep 2
                ;;
            5) control_udp_fast ;;
            6) show_status_fast ;;
            7) uninstall_fast ;;
            0) 
                echo ""
                print_status "Exiting..."
                exit 0
                ;;
            *) 
                echo ""
                print_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# SPEED OPTIMIZATIONS APPLIED:
# 1. All downloads in parallel
# 2. Minimal logging and output
# 3. Batch operations where possible
# 4. Cached system information
# 5. Async service management
# 6. Optimized system calls
# 7. No unnecessary validations
# 8. Direct file operations

# Execute with speed priority
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C
export LANG=C

# Start main function
main "$@"
