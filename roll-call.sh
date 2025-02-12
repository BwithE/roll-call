#!/bin/bash

# Define color codes
ORANGE='\033[0;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to display help message
ip=$1
usage() {
    echo "Usage: $0 <ip>"
    exit 1
}

# Check if the IP variable is set
if [ -z "$ip" ]; then
    usage
fi

echo "
+---------------------------+
|         ROLL-CALL         |
|  Target enumeration v1.0  |
+---------------------------+
"
# create main directory
mkdir -p $ip

# Create dashboard report
exec > >(tee $ip/REPORT.txt) 2>&1

# initial nmap scan
  mkdir -p $ip/port_scan
  echo -e "[+] Starting nmap port scan:"
  echo "COMMAND: nmap -p- --open $ip" > $ip/port_scan/nmap_ports.txt
  echo -e "\n\n\n" >> $ip/port_scan/nmap_ports.txt
  nmap -p- -Pn --open $ip >> $ip/port_scan/nmap_ports.txt

# open ports
  ports=$(cat $ip/port_scan/nmap_ports.txt | egrep open | egrep "tcp|udp" | egrep -o "^[0-9]+")
  for i in $ports
  do
      echo -e "${ORANGE}[info] Open Port: $i${NC}"
  done


#####################
# nmap service scan #
#####################
echo -e "[+] Starting nmap service scan:"
for i in $ports
do
    sleep 1
    # create directories on ports
    mkdir -p $ip/${i}_info
    echo "COMMAND: nmap -A -p $i $ip" > $ip/${i}_info/nmap_port_${i}_service.txt
    echo -e "\n\n\n" >> $ip/${i}_info/nmap_port_${i}_service.txt
    nmap -sV -p $i $ip >> $ip/${i}_info/nmap_port_${i}_service.txt
    sirs=$(cat $ip/${i}_info/nmap_port_${i}_service.txt | egrep open | egrep "^$i" )
    echo -e "${ORANGE}[info] $sirs${NC}"
    services=$(cat $ip/${i}_info/nmap_port_${i}_service.txt | egrep "^[0-9]+++++"| egrep "$i" | awk '{print $3}')
    sleep 1


    ##############################
    # the bread and butter cycle #
    ##############################
    for service in $services; do 
          # rename port directories into service port directories
        mv $ip/${i}_info $ip/${i}_$service\_info

        case $service in
            http|https)
                sleep 1
                # gobuster for directories
                echo -e "[+] Starting http enumeration with gobuster/dirb/nikto on Port: $i"
                echo "COMMAND: gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -q" > $ip/${i}_http_info/gobuster_directories.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/gobuster_directories.txt
                gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -q >> $ip/${i}_http_info/gobuster_directories.txt & 
                #godir_pid=$!
                #echo -e "${ORANGE}[info] Please review $ip/${i}_http_info/gobuster_directories.txt${NC}"
                sleep 1

                # gobuster for files
                echo "COMMAND: gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -q " > $ip/${i}_http_info/gobuster_files.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/gobuster_files.txt
                gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -q >> $ip/${i}_http_info/gobuster_files.txt &
                #gofile_pid=$!
                #echo -e "${ORANGE}[info] Please review: $ip/${i}_http_info/gobuster_files.txt${NC}"
                sleep 1

                # dirb for directories
                echo "COMMAND: dirb http://$ip:$i -l /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt" > $ip/${i}_http_info/dirb_directories.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/dirb_directories.txt
                dirbdir=$(dirb http://$ip:$i -l /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt >> $ip/${i}_http_info/dirb_directories.txt &)
                #dirbydir_pid=$!
                #echo -e "${ORANGE}[info] Please review: $ip/${i}_http_info/dirb_directories.txt${NC}"
                sleep 1

                # dirb for files
                echo "COMMAND: dirb http://$ip:$i -l /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt" > $ip/${i}_http_info/dirb_files.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/dirb_files.txt
                dirbfile=$(dirb http://$ip:$i -l /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt >> $ip/${i}_http_info/dirb_files.txt &)
                #dirbyfile_pid=$!
                #echo -e "${ORANGE}[info] Please review: $ip/${i}_http_info/dirb_files.txt${NC}"
                sleep 1

                # nikto for vulnerability scan
                echo "COMMAND: nikto -h http://$ip:$i -Tuning 5" > $ip/${i}_http_info/nikto_scan.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/nikto_scan.txt
                nicky=$(nikto -h http://$ip:$i -Tuning 5 >> $ip/${i}_http_info/nikto_scan.txt 2>/dev/null &)
                #niktor_pid=$!
                #echo -e "${ORANGE}[info] Please review: $ip/${i}_http_info/nikto_scan.txt${NC}"
                sleep 1
                ;;
            ftp)
                sleep 1
                echo -e "[+] Starting Hydra FTP enumeration on Port: $i"
                # make sure the directory exists before writing
                mkdir -p $ip/${i}_ftp_info
                echo "COMMAND: hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$ip -V -s $i" > $ip/${i}_ftp_info/hydra_ftp_${i}.txt
                echo -e "\n\n\n" >> $ip/${i}_ftp_info/hydra_ftp_${i}.txt
                hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$ip -V -s $i >> $ip/${i}_ftp_info/hydra_ftp_${i}.txt &
                sleep 1
                results=$(egrep "^\[$i\]" $ip/${i}_ftp_info/hydra_ftp_${i}.txt)
                # handle the results and display appropriate messages (OLD REPORTING, keeping for later use)
                : '
                if [ -n "$results" ]; then
                    echo -e "${GREEN}[CREDS] $results${NC}"
                elif egrep -qw "could not be completed" "$ip/${i}_ftp_info/hydra_ftp_${i}.txt"; then
                    echo -e "${RED}[error] COULD NOT FINISH Hydra FTP enumeration: SUGGEST MANUAL ENUMERATION${NC}"
                elif egrep -qw "0 valid password found" "$ip/${i}_ftp_info/hydra_ftp_${i}.txt"; then
                    echo -e "${ORANGE}[info] 0 FTP PASSWORDS FOUND${NC}"
                else
                    echo -e "${ORANGE}[info] 0 FTP PASSWORDS FOUND${NC}"
                fi
                '
            ;;
            smb|microsoft-ds)
                sleep 1
                echo -e "[+] Starting SMB enumeration on Port: $i"
                echo "COMMAND: enum4linux $ip" >  $ip/${i}_$service\_info/enum4linux_results_${i}.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/enum4linux_results_${i}.txt
                enum4linux $ip 2>/dev/null >> $ip/${i}_$service\_info/enum4linux_results_${i}.txt &
                sleep 1

                echo "COMMAND: smbclient \\\\$ip -U '' -P '' " >  $ip/${i}_$service\_info/smbclient_results_${i}.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/smbclient_results_${i}.txt
                smbclient \\\\$ip -U '' -P '' >> $ip/${i}_$service\_info/smbclient_results_${i}.txt 2>&1 &
                sleep 1

                # handle the results and display appropriate messages (OLD REPORTING, keeping for later use)
                : '
                results=$(egrep "^\[$i]" $ip/${i}_smb_info/hydra_smb_${i}.txt)
                if [ -n "$results" ]; then
                    echo -e "${GREEN}[CREDS] $results${NC}"
                elif egrep -qw "could not be completed" "$ip/${i}_smb_info/hydra_smb_${i}.txt"; then
                    echo -e "${RED}[error] COULD DONT FINISH Hydra SMB enumeration: SUGGEST MANUAL ENUMERATION${NC}"
                elif egrep -qw "0 valid password found" "$ip/${i}_smb_info/hydra_smb_${i}.txt"; then
                    echo -e "${ORANGE}[info] 0 SMB PASSWORDS FOUND${NC}"
                else
                    echo -e "${ORANGE}[info] 0 SMB PASSWORDS FOUND${NC}"
                fi
                '
                ;;
            ssh)
                sleep 1
                echo -e "[+] Starting Hydra SSH enumeration on Port: $i"
                echo "COMMAND: hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$ip -V -s $i -t 1 2>/dev/null" > $ip/${i}_ssh_info/hydra_ssh_${i}.txt
                echo -e "\n\n\n" >> $ip/${i}_ssh_info/hydra_ssh_${i}.txt
                hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$ip -V -s $i -t 1 2>/dev/null >> $ip/${i}_ssh_info/hydra_ssh_${i}.txt &
                sleep 1
                # handle the results and display appropriate messages (OLD REPORTING, keeping for later use)
                : '                
                output_file="$ip/${i}_ssh_info/hydra_ssh_${i}.txt"
                results=$(egrep "^\[$i]" $ip/${i}_ssh_info/hydra_ssh_${i}.txt)
                if [ -n "$results" ]; then
                    echo -e "${GREEN}[CREDS] $results${NC}"
                elif egrep -qw "could not be completed" "$output_file"; then
                    echo -e "${RED}[error] COULD NOT FINISH Hydra SSH enumeration: SUGGEST MANUAL ENUMERATION${NC}"
                elif egrep -qw "0 valid password found" "$output_file"; then
                    echo -e "${ORANGE}[info] 0 SSH PASSWORDS FOUND${NC}"
                else
                    echo -e "${ORANGE}[info] 0 SSH PASSWORDS FOUND${NC}"
                fi
                '
                ;;
            dns)
                # Add any DNS related enumeration here
                ;;
            rpc|msrpc)
                sleep 1
                echo -e "[+] Starting RPC enumeration on Port: $i"
                echo "COMMAND: rpcclient -U '' -N $ip" > $ip/${i}_$service\_info/rpcclient_test.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/rpcclient_test.txt
                rpc_test=$(rpcclient -U '' -N $ip >> $ip/${i}_$service\_info/rpcclient_test.txt 2>&1 &)
                sleep 1
                ;;
            netbios|netbios-ssn)
                sleep 1
                echo -e "[+] Starting NETBIOS enumeration on Port: $i"
                echo "COMMAND: nbtscan $ip" > $ip/${i}_$service\_info/nbtscan_results.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/nbtscan_results.txt
                netbios_test=$(nbtscan $ip >> $ip/${i}_$service\_info/nbtscan_results.txt &)
                sleep 1
                ;;
        esac
    done
done





############################################################################################
# PROCESS CHECK
############################################################################################
# Function to count active processes
count_active_processes() {
    # Get counts of different processes
    ftphydra_count=$(ps aux | egrep -w 'hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    sshhydra_count=$(ps aux | egrep -w 'hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    gobuster_count=$(ps aux | egrep -w 'gobuster' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    dirb_count=$(ps aux | egrep -w 'dirb' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    nikto_count=$(ps aux | egrep -w 'nikto' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    enum4linux_count=$(ps aux | egrep -w 'enum4linux' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    rpc_count=$(ps aux | egrep -w 'rcpclient'| egrep -v "color=auto" | egrep -v "grep" | wc -l)
    netbios_count=$(ps aux | egrep -w 'nbtscan'| egrep -v "color=auto" | egrep -v "grep" | wc -l)
    smbclient_count=$(ps aux | egrep -w 'smbclient '| egrep -v "color=auto" | egrep -v "grep" | wc -l)

    total_processes_count=$(($ftphydra_count + $sshhydra_count + $gobuster_count + $dirb_count + $nikto_count + $enum4linux_count + $rpc_count + $netbios_count + $smbclient_count))
    echo $total_processes_count
}

# Check for user input while background tasks are running
echo "[+] Waiting on the background scans to finish. Press the ENTER/RETURN key to check progress."

# Loop to monitor processes
while true; do
    # Wait for a keypress without blocking other tasks
    if read -t 1 -n 1; then
        # If a key was pressed, count active processes and display
        active_processes=$(count_active_processes)
        echo "[+] Active Enumeration Processes: $active_processes"
    fi

    # Check if all processes have finished
    active_processes=$(count_active_processes)
    if [ "$active_processes" -eq 0 ]; then
        break
    fi

done

echo "[+] Enumeration complete."
