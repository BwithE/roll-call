#!/bin/bash


# Define color codes
ORANGE='\033[1;33m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'  # Yellow
PURPLE='\033[1;35m'   # Purple
PINK='\033[1;35m'     # Pink
BLUE='\033[1;34m'     # Blue
NC='\033[0m' # No Color

# Function to display help message
ip=$1
choice=$2

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
  echo -e "${ORANGE}[+] Starting nmap port/service scan:${NC}"
  echo "[COMMAND] nmap -p- -sV -Pn --open $ip"
  echo "COMMAND: nmap -p- -sV -Pn --open $ip" > $ip/port_scan/nmap_scan.txt
  echo -e "\n\n\n" >> $ip/port_scan/nmap_scan.txt
  nmap -p- -sV -Pn --open $ip >> $ip/port_scan/nmap_scan.txt

# open ports
  ports=$(cat $ip/port_scan/nmap_scan.txt | egrep open | egrep "tcp|udp" | egrep -o "^[0-9]+")
  for i in $ports
  do
      echo -e "${BLUE}[info] Open Port: $i${NC}"
  done


ports=$(cat $ip/port_scan/nmap_scan.txt | egrep open | egrep "tcp|udp" | egrep -o "^[0-9]+")
#####################
# nmap service scan #
#####################
echo -e "${ORANGE}[+] Starting service enumeration:${NC}"
for i in $ports
do
    sleep 1
    # create directories on ports
    mkdir -p $ip/${i}_info
    sirs=$(cat $ip/port_scan/nmap_scan.txt | egrep open | egrep "tcp|udp" | egrep "^$i" )
    echo -e "${BLUE}[info] $sirs${NC}"
    services=$(cat $ip/port_scan/nmap_scan.txt | egrep "^[0-9]+++++"| egrep "$i" | awk '{print $3}')
    sleep 1


    ##############################
    # the bread and butter cycle #
    ##############################
    for service in $services; do 
          # rename port directories into service port directories
        mv $ip/${i}_info $ip/${i}_$service\_info

        case $service in
            http|https|http?)
                sleep 1
                # gobuster for directories
                echo -e "${ORANGE}[+] Starting http enumeration with gobuster/dirb/nikto/whatweb on Port: $i${NC}"
                echo "[COMMAND] gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -q"
                echo "COMMAND: gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -q" > $ip/${i}_http_info/gobuster_directories.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/gobuster_directories.txt
                gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -q >> $ip/${i}_http_info/gobuster_directories.txt & 
                #godir_pid=$!
                #echo -e "${BLUE}[info] Please review $ip/${i}_http_info/gobuster_directories.txt${NC}"
                sleep 3

                # gobuster for files
                echo "[COMMAND] gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -q "
                echo "COMMAND: gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -q " > $ip/${i}_http_info/gobuster_files.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/gobuster_files.txt
                gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -q >> $ip/${i}_http_info/gobuster_files.txt &
                #gofile_pid=$!
                #echo -e "${BLUE}[info] Please review: $ip/${i}_http_info/gobuster_files.txt${NC}"
                sleep 3

                # dirb for directories
                echo "[COMMAND] dirb http://$ip:$i /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt"
                echo "COMMAND: dirb http://$ip:$i /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt" > $ip/${i}_http_info/dirb_directories.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/dirb_directories.txt
                dirbdir=$(dirb http://$ip:$i /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt >> $ip/${i}_http_info/dirb_directories.txt &)
                #dirbydir_pid=$!
                #echo -e "${BLUE}[info] Please review: $ip/${i}_http_info/dirb_directories.txt${NC}"
                sleep 3

                # dirb for files
                echo "[COMMAND] dirb http://$ip:$i /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt"
                echo "COMMAND: dirb http://$ip:$i /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt" > $ip/${i}_http_info/dirb_files.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/dirb_files.txt
                dirbfile=$(dirb http://$ip:$i /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt >> $ip/${i}_http_info/dirb_files.txt &)
                #dirbyfile_pid=$!
                #echo -e "${BLUE}[info] Please review: $ip/${i}_http_info/dirb_files.txt${NC}"
                sleep 3

                # nikto for vulnerability scan
                echo "[COMMAND] nikto -h http://$ip:$i -Tuning 5"
                echo "COMMAND: nikto -h http://$ip:$i -Tuning 5" > $ip/${i}_http_info/nikto_scan.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/nikto_scan.txt
                nicky=$(nikto -h http://$ip:$i -Tuning 5 >> $ip/${i}_http_info/nikto_scan.txt 2>/dev/null &)
                #niktor_pid=$!
                #echo -e "${BLUE}[info] Please review: $ip/${i}_http_info/nikto_scan.txt${NC}"
                sleep 3

                # whatweb for vulnerability scan
                echo "[COMMAND] whatweb http://$ip:$i "
                echo "COMMAND: whatweb http://$ip:$i " > $ip/${i}_http_info/whatweb_scan.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/whatweb_scan.txt
                whatwebber=$(whatweb http://$ip:$i >> $ip/${i}_http_info/whatweb_scan.txt 2>/dev/null &)
                #niktor_pid=$!
                #echo -e "${BLUE}[info] Please review: $ip/${i}_http_info/nikto_scan.txt${NC}"
                sleep 1
                ;;
            ftp|ftp?)
                sleep 1
                echo -e "${ORANGE}[+] Starting Hydra FTP enumeration on Port: $i${NC}"
                # make sure the directory exists before writing
                mkdir -p $ip/${i}_ftp_info
                echo "[COMMAND] hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$ip -V -s $i"
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
                    echo -e "${BLUE}[info] 0 FTP PASSWORDS FOUND${NC}"
                else
                    echo -e "${BLUE}[info] 0 FTP PASSWORDS FOUND${NC}"
                fi
                '
            ;;
            smb|microsoft-ds|microsoft-ds?)
                sleep 1
                echo -e "${ORANGE}[+] Starting SMB enumeration on Port: $i${NC}"
                echo "[COMMAND] enum4linux $ip"
                echo "COMMAND: enum4linux $ip" >  $ip/${i}_$service\_info/enum4linux_results_${i}.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/enum4linux_results_${i}.txt
                enum4linux $ip 2>/dev/null >> $ip/${i}_$service\_info/enum4linux_results_${i}.txt &
                sleep 1
                echo "[COMMAND] smbclient -N -L \\\\$ip "
                echo "COMMAND: smbclient -N -L \\\\$ip " >  $ip/${i}_$service\_info/smbclient_results_${i}.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/smbclient_results_${i}.txt
                smbclient -N -L \\\\$ip >> $ip/${i}_$service\_info/smbclient_results_${i}.txt 2>&1 &
                sleep 1

                # handle the results and display appropriate messages (OLD REPORTING, keeping for later use)
                : '
                results=$(egrep "^\[$i]" $ip/${i}_smb_info/hydra_smb_${i}.txt)
                if [ -n "$results" ]; then
                    echo -e "${GREEN}[CREDS] $results${NC}"
                elif egrep -qw "could not be completed" "$ip/${i}_smb_info/hydra_smb_${i}.txt"; then
                    echo -e "${RED}[error] COULD DONT FINISH Hydra SMB enumeration: SUGGEST MANUAL ENUMERATION${NC}"
                elif egrep -qw "0 valid password found" "$ip/${i}_smb_info/hydra_smb_${i}.txt"; then
                    echo -e "${BLUE}[info] 0 SMB PASSWORDS FOUND${NC}"
                else
                    echo -e "${BLUE}[info] 0 SMB PASSWORDS FOUND${NC}"
                fi
                '
                ;;
            ssh|ssh?)
                function_ssh () {
                sleep 1
                echo -e "${ORANGE}[+] Starting Hydra SSH enumeration on Port: $i${NC}"
                echo "[COMMAND] hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$ip -V -s $i -t 1 2>/dev/null"
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
                    echo -e "${BLUE}[info] 0 SSH PASSWORDS FOUND${NC}"
                else
                    echo -e "${BLUE}[info] 0 SSH PASSWORDS FOUND${NC}"
                fi
                '
                }
                ;;
            dns|dns?)
                # to be added
                ;;
            rpc|msrpc|msrpc?)
                sleep 1
                echo -e "${ORANGE}[+] Starting RPC enumeration on Port: $i${NC}"
                echo "[COMMAND] rpcclient -U '' -N $ip" 
                echo "COMMAND: rpcclient -U '' -N $ip" > $ip/${i}_$service\_info/rpcclient_test.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/rpcclient_test.txt
                rpc_test=$(rpcclient -U '' -N $ip >> $ip/${i}_$service\_info/rpcclient_test.txt 2>&1 &)
                sleep 1
                ;;
            netbios|netbios-ssn|netbios-ssn?|netbios?)
                sleep 1
                echo -e "${ORANGE}[+] Starting NETBIOS enumeration on Port: $i${NC}"
                echo "[COMMAND] nbtscan $ip"
                echo "COMMAND: nbtscan $ip" > $ip/${i}_$service\_info/nbtscan_results.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/nbtscan_results.txt
                netbios_test=$(nbtscan $ip >> $ip/${i}_$service\_info/nbtscan_results.txt &)
                sleep 1
                ;;
            smtp|smtp?|mail)
                sleep 1
                echo -e "${ORANGE}[+] Starting SMTP enumeration on Port: $i${NC}"
                echo "[COMMAND] nmap -p ${i} --script=smtp-enum-users $ip"
                echo "COMMAND: nmap -p ${i} --script=smtp-enum-users $ip" > $ip/${i}_$service\_info/smtp_nmap_enumusers_script.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/smtp_nmap_enumusers_script.txt
                smtp_enumusers=$(nmap -p ${i} --script=smtp-enum-users $ip >> $ip/${i}_$service\_info/smtp_nmap_enumusers_script.txt &)
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
    whatweb_count=$(ps aux | grep -w 'whatweb' | egrep -v 'color=auto' | egrep -v 'grep' | wc -l)
    enum4linux_count=$(ps aux | egrep -w 'enum4linux' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    rpc_count=$(ps aux | egrep -w 'rcpclient'| egrep -v "color=auto" | egrep -v "grep" | wc -l)
    netbios_count=$(ps aux | egrep -w 'nbtscan'| egrep -v "color=auto" | egrep -v "grep" | wc -l)
    smbclient_count=$(ps aux | egrep -w 'smbclient '| egrep -v "color=auto" | egrep -v "grep" | wc -l)
    smtp_enumusers_count=$(ps aux | egrep -w 'nmap -p 25 --script=smtp-enum-users' | egrep -v "color=auto" | egrep -v "grep" | wc -l )

    total_processes_count=$(($smtp_enumusers_count + $whatweb_count + $ftphydra_count + $sshhydra_count + $gobuster_count + $dirb_count + $nikto_count + $enum4linux_count + $rpc_count + $netbios_count + $smbclient_count))
    echo $total_processes_count
}

# Check for user input while background tasks are running
echo -e "${YELLOW}[+] Waiting on the background scans to finish. Press the ENTER/RETURN key to check progress.${NC}"
active_processes=$(count_active_processes)
echo -e "${PINK}[endgame] Active Enumeration Processes: $active_processes${NC}"
# Loop to monitor processes
while true; do
    # Wait for a keypress without blocking other tasks
    if read -t 1 -n 1; then
        # If a key was pressed, count active processes and display
        echo -e "${YELLOW}[+] Waiting on the background scans to finish. Press the ENTER/RETURN key to check progress.${NC}"
        active_processes=$(count_active_processes)
        echo -e "${PINK}[endgame] Active Enumeration Processes: $active_processes${NC}"
    fi

    # Check if all processes have finished
    active_processes=$(count_active_processes)
    if [ "$active_processes" -eq 0 ]; then
        break
    fi

done

echo -e "${BLUE}[+] Enumeration complete.${NC}"


##################################################
# useful info gathered
##################################################
echo -e "${ORANGE}[+] Information gathered:${NC}"
for i in $ports
do
    sirs=$(cat $ip/port_scan/nmap_scan.txt | egrep open | egrep "tcp|udp" | egrep "^$i" )
    services=$(cat $ip/port_scan/nmap_scan.txt | egrep "^[0-9]+++++"| egrep "$i" | awk '{print $3}')
    
    # loop through each service to dump useful info found
    for service in $services; do 
    
        case $service in
                http|https|http?)
                    sleep 1
                    # gobuster for directories
                    echo -e "${GREEN}[+] Useful gobuster info found for http on port ${i}:${NC}"
                    egrep "\(Status:" $ip/${i}_http_info/gobuster_directories.txt
                    egrep "\(Status:" $ip/${i}_http_info/gobuster_files.txt
                    echo -e "${GREEN}[+] Useful dirb info found for http on port ${i}:${NC}"
                    egrep '\(CODE:[0-9]+' $ip/${i}_http_info/dirb_directories.txt
                    egrep '\(CODE:[0-9]+' $ip/${i}_http_info/dirb_files.txt
                    ;;
                ftp|ftp?)
                    sleep 1
                    results=$(egrep "^\[${i}\]" $ip/${i}_ftp_info/hydra_ftp_${i}.txt)
                    if [ -n "$results" ]
                    then
                        echo -e "${GREEN}[+] Useful info found for FTP:${NC}"
                        echo $results
                    fi
                    ;;
                smb|microsoft-ds|microsoft-ds?)
                    sleep 1
                    # handle the results and display appropriate messages (OLD REPORTING, keeping for later use)
                    : '
                    results=$(egrep "^\[$i]" $ip/${i}_smb_info/hydra_smb_${i}.txt)
                    if [ -n "$results" ]; then
                        echo -e "${GREEN}[CREDS] $results${NC}"
                    elif egrep -qw "could not be completed" "$ip/${i}_smb_info/hydra_smb_${i}.txt"; then
                        echo -e "${RED}[error] COULD DONT FINISH Hydra SMB enumeration: SUGGEST MANUAL ENUMERATION${NC}"
                    elif egrep -qw "0 valid password found" "$ip/${i}_smb_info/hydra_smb_${i}.txt"; then
                        echo -e "${BLUE}[info] 0 SMB PASSWORDS FOUND${NC}"
                    else
                        echo -e "${BLUE}[info] 0 SMB PASSWORDS FOUND${NC}"
                    fi
                    '
                    ;;
                ssh|ssh?)
                    # handle the results and display appropriate messages (OLD REPORTING, keeping for later use)
                    : '                
                    output_file="$ip/${i}_ssh_info/hydra_ssh_${i}.txt"
                    results=$(egrep "^\[$i]" $ip/${i}_ssh_info/hydra_ssh_${i}.txt)
                    if [ -n "$results" ]; then
                        echo -e "${GREEN}[CREDS] $results${NC}"
                    elif egrep -qw "could not be completed" "$output_file"; then
                        echo -e "${RED}[error] COULD NOT FINISH Hydra SSH enumeration: SUGGEST MANUAL ENUMERATION${NC}"
                    elif egrep -qw "0 valid password found" "$output_file"; then
                        echo -e "${BLUE}[info] 0 SSH PASSWORDS FOUND${NC}"
                    else
                        echo -e "${BLUE}[info] 0 SSH PASSWORDS FOUND${NC}"
                    fi
                    '
                    ;;
                dns|dns?)
                    # to be added
                    ;;
                rpc|msrpc|msrpc?)
                    # to be added
                    ;;
                netbios|netbios-ssn|netbios-ssn?|netbios?)
                    # to be added
                    ;;
                smtp|smtp?|mail)
                    # to be added
                    ;;
        esac
    done
done

echo -e "${BLUE}[+] Roll-Call : COMPLETE.${NC}"
