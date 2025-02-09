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
        --no-ssh)
        
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
+---------------------------+
|         ROLL-CALL         |
|  Target enumeration v1.0  |
+---------------------------+
"
# Create main directory
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


# nmap service scan
  echo -e "[+] Starting nmap service scan:"
  for i in $ports
  do
      # create directories on ports
      mkdir -p $ip/${i}_info
      echo "COMMAND: nmap -A -p $i $ip" > $ip/${i}_info/nmap_port_${i}_service.txt
      echo -e "\n\n\n" >> $ip/${i}_info/nmap_port_${i}_service.txt
      nmap -sV -p $i $ip >> $ip/${i}_info/nmap_port_${i}_service.txt
      sirs=$(cat $ip/${i}_info/nmap_port_${i}_service.txt | egrep open | egrep "^$i" )
      echo -e "${ORANGE}[info] $sirs${NC}"
      services=$(cat $ip/${i}_info/nmap_port_${i}_service.txt | egrep "^[0-9]+++++"| egrep "$i" | awk '{print $3}')
  done


############################
# the bread and butter cycle
############################
for i in $ports
do
    services=$(cat $ip/${i}_info/nmap_port_${i}_service.txt | egrep "^[0-9]+++++"| egrep "$i" | awk '{print $3}')

    # loop through each port and run tools vs services
    for service in $services; do 
          # rename port directories into service port directories
        mv $ip/${i}_info $ip/${i}_$service\_info

        case $service in
            http|https)
                # Gobuster for directories
                echo -e "[+] Starting http enumeration with Gobuster for directories on Port: $i"
                echo "COMMAND: gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -q" > $ip/${i}_http_info/gobuster_directories.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/gobuster_directories.txt
                gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -q >> $ip/${i}_http_info/gobuster_directories.txt &
                godir_pid=$!
                echo -e "${ORANGE}[info] Please review $ip/${i}_http_info/gobuster_directories.txt${NC}"

                # Gobuster for files
                echo -e "[+] Starting http enumeration with Gobuster for files on Port: $i"
                echo "COMMAND: gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -q " > $ip/${i}_http_info/gobuster_files.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/gobuster_files.txt
                gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -q >> $ip/${i}_http_info/gobuster_files.txt &
                gofile_pid=$!
                echo -e "${ORANGE}[info] Please review: $ip/${i}_http_info/gobuster_files.txt${NC}"

                # Dirb for directories
                echo -e "[+] Starting http enumeration with Dirb for directories on Port: $i"
                echo "COMMAND: dirb http://$ip:$i -l /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt" > $ip/${i}_http_info/dirb_directories.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/dirb_directories.txt
                dirbdir=$(dirb http://$ip:$i -l /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt >> $ip/${i}_http_info/dirb_directories.txt &)
                dirbydir_pid=$!
                echo -e "${ORANGE}[info] Please review: $ip/${i}_http_info/dirb_directories.txt${NC}"

                # Dirb for files
                echo -e "[+] Starting http enumeration with Dirb for files on Port: $i"
                echo "COMMAND: dirb http://$ip:$i -l /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt" > $ip/${i}_http_info/dirb_files.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/dirb_files.txt
                dirbfile=$(dirb http://$ip:$i -l /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt >> $ip/${i}_http_info/dirb_files.txt &)
                dirbyfile_pid=$!
                echo -e "${ORANGE}[info] Please review: $ip/${i}_http_info/dirb_files.txt${NC}"

                # Nikto for vulnerability scan
                echo -e "[+] Starting http enumeration with Nikto on Port: $i"
                echo "COMMAND: nikto -h http://$ip:$i -Tuning 5" > $ip/${i}_http_info/nikto_scan.txt
                echo -e "\n\n\n" >> $ip/${i}_http_info/nikto_scan.txt
                nicky=$(nikto -h http://$ip:$i -Tuning 5 >> $ip/${i}_http_info/nikto_scan.txt 2>/dev/null &)
                niktor_pid=$!
                echo -e "${ORANGE}[info] Please review: $ip/${i}_http_info/nikto_scan.txt${NC}"
                ;;
            ftp)
                echo -e "[+] Starting Hydra FTP enumeration on Port: $i"
                # Make sure the directory exists before writing
                mkdir -p $ip/${i}_ftp_info
                echo "COMMAND: hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$ip -V -s $i" > $ip/${i}_ftp_info/hydra_ftp_${i}.txt
                echo -e "\n\n\n" >> $ip/${i}_ftp_info/hydra_ftp_${i}.txt
                hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$ip -V -s $i >> $ip/${i}_ftp_info/hydra_ftp_${i}.txt &
                sleep 1
                results=$(egrep "^\[$i\]" $ip/${i}_ftp_info/hydra_ftp_${i}.txt)
                # Handle the results and display appropriate messages
                if [ -n "$results" ]; then
                    echo -e "${GREEN}[CREDS] $results${NC}"
                elif egrep -qw "could not be completed" "$ip/${i}_ftp_info/hydra_ftp_${i}.txt"; then
                    echo -e "${RED}[error] COULDN'T FINISH Hydra FTP enumeration: SUGGEST MANUAL ENUMERATION${NC}"
                elif egrep -qw "0 valid password found" "$ip/${i}_ftp_info/hydra_ftp_${i}.txt"; then
                    echo -e "${ORANGE}[info] 0 FTP PASSWORDS FOUND${NC}"
                else
                    echo -e "${ORANGE}[info] 0 FTP PASSWORDS FOUND${NC}"
                fi
            ;;
            smb)
                echo -e "[+] Starting Hydra SMB enumeration on Port: $i"
                echo "COMMAND: hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/smb-betterdefaultpasslist.txt smb://$ip -V -s $i" > $ip/${i}_smb_info/hydra_smb_${i}.txt
                echo -e "\n\n\n" >> $ip/${i}_smb_info/hydra_smb_${i}.txt
                hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/smb-betterdefaultpasslist.txt smb://$ip -V -s $i >> $ip/${i}_smb_info/hydra_smb_${i}.txt &
                sleep 1
                results=$(egrep "^\[$i]" $ip/${i}_smb_info/hydra_smb_${i}.txt)
                if [ -n "$results" ]; then
                    echo -e "${GREEN}[CREDS] $results${NC}"
                elif egrep -qw "could not be completed" "$ip/${i}_smb_info/hydra_smb_${i}.txt"; then
                    echo -e "${RED}[error] COULDN'T FINISH Hydra SMB enumeration: SUGGEST MANUAL ENUMERATION${NC}"
                elif egrep -qw "0 valid password found" "$ip/${i}_smb_info/hydra_smb_${i}.txt"; then
                    echo -e "${ORANGE}[info] 0 SMB PASSWORDS FOUND${NC}"
                else
                    echo -e "${ORANGE}[info] 0 SMB PASSWORDS FOUND${NC}"
                fi
                ;;
            ssh)
                echo -e "[+] Starting Hydra SSH enumeration on Port: $i"
                echo "COMMAND: hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$ip -V -s $i -t 1 2>/dev/null" > $ip/${i}_ssh_info/hydra_ssh_${i}.txt
                echo -e "\n\n\n" >> $ip/${i}_ssh_info/hydra_ssh_${i}.txt
                hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$ip -V -s $i -t 1 2>/dev/null >> $ip/${i}_ssh_info/hydra_ssh_${i}.txt &
                sleep 1
                output_file="$ip/${i}_ssh_info/hydra_ssh_${i}.txt"
                results=$(egrep "^\[$i]" $ip/${i}_ssh_info/hydra_ssh_${i}.txt)
                if [ -n "$results" ]; then
                    echo -e "${GREEN}[CREDS] $results${NC}"
                elif egrep -qw "could not be completed" "$output_file"; then
                    echo -e "${RED}[error] COULDN'T FINISH Hydra SSH enumeration: SUGGEST MANUAL ENUMERATION${NC}"
                elif egrep -qw "0 valid password found" "$output_file"; then
                    echo -e "${ORANGE}[info] 0 SSH PASSWORDS FOUND${NC}"
                else
                    echo -e "${ORANGE}[info] 0 SSH PASSWORDS FOUND${NC}"
                fi
                ;;
            dns)
                # Add any DNS related enumeration here
                ;;
        esac
    done
done


echo "[+] Waiting on the background scans to finish." >&2

# Initial counts
ftphydra_count=$(ps aux | egrep -w 'hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
sshhydra_count=$(ps aux | egrep -w 'hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
smbhydra_count=$(ps aux | egrep -w 'hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/smb-betterdefaultpasslist.txt smb' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
gobuster_count=$(ps aux | egrep -w 'gobuster' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
dirb_count=$(ps aux | egrep -w 'dirb' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
nikto_count=$(ps aux | egrep -w 'nikto' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
enum4linux_count=$(ps aux | egrep -w 'enum4linux' | egrep -v "color=auto" | egrep -v "grep" | wc -l)

# Loop to check if all processes have finished
ftphydra_done=false
sshhydra_done=false
smbhydra_done=false
gobuster_done=false
dirb_done=false
nikto_done=false
enum4linux_done=false

while true; do
    # Check if any process counts are not 0
    ftphydra_count=$(ps aux | egrep -w 'hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    sshhydra_count=$(ps aux | egrep -w 'hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    smbhydra_count=$(ps aux | egrep -w 'hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/smb-betterdefaultpasslist.txt smb' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    gobuster_count=$(ps aux | egrep -w 'gobuster' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    dirb_count=$(ps aux | egrep -w 'dirb' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    nikto_count=$(ps aux | egrep -w 'nikto' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    enum4linux_count=$(ps aux | egrep -w 'enum4linux' | egrep -v "color=auto" | egrep -v "grep" | wc -l)

    # If any process count reaches 0 and hasn't been reported yet, print the message and set the flag
    if [ "$ftphydra_count" -eq 0 ] && [ "$ftphydra_done" = false ]; then
        echo -e "${ORANGE}[info] Hydra FTP process has finished.${NC}" >&2
        ftphydra_done=true
    fi

    if [ "$sshhydra_count" -eq 0 ] && [ "$sshhydra_done" = false ]; then
        echo -e "${ORANGE}[info] Hydra SSH process has finished.${NC}" >&2
        sshhydra_done=true
    fi

    if [ "$smbhydra_count" -eq 0 ] && [ "$smbhydra_done" = false ]; then
        echo -e "${ORANGE}[info] Hydra SMB process has finished.${NC}" >&2
        smbhydra_done=true
    fi

    if [ "$gobuster_count" -eq 0 ] && [ "$gobuster_done" = false ]; then
        echo -e "${ORANGE}[info] Gobuster process has finished.${NC}" >&2
        gobuster_done=true
    fi

    if [ "$dirb_count" -eq 0 ] && [ "$dirb_done" = false ]; then
        echo -e "${ORANGE}[info] Dirb process has finished.${NC}" >&2
        dirb_done=true
    fi

    if [ "$nikto_count" -eq 0 ] && [ "$nikto_done" = false ]; then
        echo -e "${ORANGE}[info] Nikto process has finished.${NC}" >&2
        nikto_done=true
    fi

    if [ "$enum4linux_count" -eq 0 ] && [ "$enum4linux_done" = false ]; then
        echo -e "${ORANGE}[info] Enum4Linux process has finished.${NC}" >&2
        enum4linux_done=true
    fi

    # If all counts are 0, exit the loop
    if [ "$gobuster_count" -eq 0 ] && [ "$dirb_count" -eq 0 ] && [ "$nikto_count" -eq 0 ] && [ "$ftphydra_count" -eq 0 ] && [ "$sshhydra_count" -eq 0 ] && [ "$smbhydra_count" -eq 0 ] && [ "$enum4linux_count" -eq 0 ]; then
        break
    fi

    # Print the current remaining process counts
    echo "[+] Remaining processes
    - Enum4Linux: $enum4linux_count
    - Dirb: $dirb_count
    - Gobuster: $gobuster_count
    - Hydra FTP: $ftphydra_count
    - Hydra SMB: $smbhydra_count
    - Hydra SSH: $sshhydra_count
    - Nikto: $nikto_count
    " >&2
    
    sleep 60
done

echo ""
echo "[+] Enumeration complete."
echo ""
exit


