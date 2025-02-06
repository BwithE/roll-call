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

# creates dashboard report
exec > >(tee $ip\_report.txt) 2>&1

function nmap_query {
    echo -e "[+] Starting nmap port scan:"
    nmap -p- --open $ip > nmap_ports.txt
}

function open_ports {
    ports=$(cat nmap_ports.txt | egrep open | egrep "tcp|udp" | egrep -o "^[0-9]++++")
    for i in $ports
    do
        echo -e "${ORANGE}[info] Open Port: $i${NC}"
    done
}

function nmap_service {
    echo -e "[+] Starting nmap service scan:"
    for i in $ports
    do
        nmap -A -p $i $ip > nmap_port_$i\_service.txt
    done
}

function service_enumeration {
    for i in $ports
    do
        services=$(cat nmap_port_$i\_service.txt | egrep open | egrep "^$i" )
        echo -e "${ORANGE}[info] $services${NC}"
    done
}

function ftp_enumeration {
    for i in $ports
    do
        ftp_query=$(cat nmap_port_$i\_service.txt | egrep open | egrep "^$i" | egrep -wo ftp)
        ftp_port=$(cat nmap_port_$i\_service.txt | egrep open | egrep "^$i" | egrep -w ftp | cut -d '/' -f 1)
        if [ -z "$ftp_port" ]
        then
	    continue
        else
            echo -e "[+] Starting Hydra FTP enumeration on Port: $ftp_port" 
            hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$ip -V -s $ftp_port > ftp_port_$ftp_port\_enumeration.txt
	    sleep 1
            results=$(egrep "^\[$ftp_port]" ftp_port_$ftp_port\_enumeration.txt)
            echo -e "${GREEN}[NUGGET] $results${NC}"
        fi
    done
}


function ssh_enumeration {
    for i in $ports
    do
        ssh_query=$(cat nmap_port_$i\_service.txt | egrep open | egrep "^$i" | egrep -wo ssh)
        ssh_port=$(cat nmap_port_$i\_service.txt | egrep open | egrep "^$i" | egrep -w ssh | cut -d '/' -f 1)
        if [ -z "$ssh_port" ]
        then
            continue
        else
            echo -e "[+] Starting Hydra SSH enumeration on Port: $ssh_port" 
            hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$ip -V -s $ssh_port -t 1 2>/dev/null > ssh_port_$ssh_port\_enumeration.txt
            sleep 1
            results=$(egrep "^\[$ssh_port]" ssh_port_$ssh_port\_enumeration.txt)
            if $(cat ssh_port_$ssh_port\_enumeration.txt | grep -q "could not be completed")
	    then
                echo -e "${RED}[error] COULDN'T FINISH Hydra SSH enumeration: SUGGEST MANUAL ENUMERATION${NC}"
            elif $(cat ssh_port_$ssh_port\_enumeration.txt | grep -q "0 valid password found")
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

service_enumeration

ftp_enumeration

ssh_enumeration
