#!/bin/bash

# Define color codes
ORANGE='\033[0;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t)
            ip="$2"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

# Function to display help message
usage() {
    echo "Usage: $0 -t <ip>"
    exit 1
}

# Check if the IP variable is set
if [ -z "$ip" ]; then
    usage
fi

echo "
██████╗  ██████╗ ██╗     ██╗       ██████╗ █████╗ ██╗     ██╗     
██╔══██╗██╔═══██╗██║     ██║      ██╔════╝██╔══██╗██║     ██║     
██████╔╝██║   ██║██║     ██║█████╗██║     ███████║██║     ██║     
██╔══██╗██║   ██║██║     ██║╚════╝██║     ██╔══██║██║     ██║     
██║  ██║╚██████╔╝███████╗███████╗ ╚██████╗██║  ██║███████╗███████╗
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝

Target enumeration v1.0
+----------------------------------------------------------------+
"
# Create main directory
mkdir -p $ip

# Create dashboard report
exec > >(tee $ip/REPORT.txt) 2>&1

function nmap_query {
    mkdir -p $ip/port_scan
    echo -e "[+] Starting nmap port scan:"
    echo "COMMAND: nmap -p- --open $ip" > $ip/port_scan/nmap_ports.txt
    echo -e "\n\n\n" >> $ip/port_scan/nmap_ports.txt
    nmap -p- --open $ip >> $ip/port_scan/nmap_ports.txt
}

function open_ports {
    ports=$(cat $ip/port_scan/nmap_ports.txt | egrep open | egrep "tcp|udp" | egrep -o "^[0-9]+")
    for i in $ports
    do
        echo -e "${ORANGE}[info] Open Port: $i${NC}"
    done
}

function nmap_service {
    echo -e "[+] Starting nmap service scan:"
    for i in $ports
    do
        mkdir -p $ip/${i}_info
        echo "COMMAND: nmap -A -p $i $ip" > $ip/${i}_info/nmap_port_${i}_service.txt
        echo -e "\n\n\n" >> $ip/${i}_info/nmap_port_${i}_service.txt
        nmap -A -p $i $ip >> $ip/${i}_info/nmap_port_${i}_service.txt
        services=$(cat $ip/${i}_info/nmap_port_${i}_service.txt | egrep open | egrep "^$i" )
        echo -e "${ORANGE}[info] $services${NC}"
        sir=$(cat $ip/${i}_info/nmap_port_${i}_service.txt | egrep "^[0-9]+++++"| egrep "$i" | awk '{print $3}')
        mv $ip/${i}_info $ip/${i}_$sir\_info
    done
}


function ftp_enumeration {
    for i in $ports
    do
        ftp_query=$(cat $ip/${i}_ftp_info/nmap_port_${i}_service.txt 2>/dev/null | egrep open | egrep "^$i" | egrep -wo ftp)
        ftp_port=$(cat $ip/${i}_ftp_info/nmap_port_${i}_service.txt 2>/dev/null | egrep open | egrep "^$i" | egrep -w ftp | cut -d '/' -f 1)
        if [ -z "$ftp_port" ]
        then
            continue
        else
            echo -e "[+] Starting Hydra FTP enumeration on Port: $ftp_port"
            echo "COMMAND: hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$ip -V -s $ftp_port" > $ip/${i}_ftp_info/hydra_ftp_${ftp_port}.txt
            echo -e "\n\n\n" >> $ip/${i}_ftp_info/hydra_ftp_${ftp_port}.txt
            hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$ip -V -s $ftp_port >> $ip/${i}_ftp_info/hydra_ftp_${ftp_port}.txt
            sleep 1
            results=$(egrep "^\[$ftp_port]" $ip/${i}_ftp_info/hydra_ftp_${ftp_port}.txt)
            echo -e "${GREEN}[NUGGET] $results${NC}"
        fi
    done
}

function ssh_enumeration {
    for i in $ports
    do
        ssh_query=$(cat $ip/${i}_ssh_info/nmap_port_${i}_service.txt 2>/dev/null | egrep open | egrep "^$i" | egrep -wo ssh)
        ssh_port=$(cat $ip/${i}_ssh_info/nmap_port_${i}_service.txt 2>/dev/null | egrep open | egrep "^$i" | egrep -w ssh | cut -d '/' -f 1)
        if [ -z "$ssh_port" ]
        then
            continue
        else
            echo -e "[+] Starting Hydra SSH enumeration on Port: $ssh_port"
            echo "COMMAND: hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$ip -V -s $ssh_port -t 1 2>/dev/null" > $ip/${i}_ssh_info/hydra_ssh_${ssh_port}.txt
            echo -e "\n\n\n" >> $ip/${i}_ssh_info/hydra_ssh_${ssh_port}.txt
            hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$ip -V -s $ssh_port -t 1 2>/dev/null >> $ip/${i}_ssh_info/hydra_ssh_${ssh_port}.txt
            sleep 1
            results=$(egrep "^\[$ssh_port]" $ip/${i}_ssh_info/hydra_ssh_${ssh_port}.txt)
            if $(cat $ip/${i}_ssh_info/hydra_ssh_${ssh_port}.txt | grep -q "could not be completed")
            then
                echo -e "${RED}[error] COULDN'T FINISH Hydra SSH enumeration: SUGGEST MANUAL ENUMERATION${NC}"
            elif $(cat $ip/${i}_ssh_info/hydra_ssh_${ssh_port}.txt | grep -q "0 valid password found")
            then
                echo -e "${ORANGE}[info] 0 PASSWORDS FOUND${NC}"
            else
                echo -e "${GREEN}[NUGGET] $results${NC}"
            fi
        fi
    done
}

nmap_query

open_ports

nmap_service

ftp_enumeration

ssh_enumeration
