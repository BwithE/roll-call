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

# Initialize variables
ip=""
username=""
password=""
workgroup_domain=""

# Function to display help message
usage() {
    echo "Usage: $0 -t <ip> [-u <username> -p <password> -d <domain/workgroup>]"
    exit 1
}

# Parse command-line arguments
while getopts "t:u:p:d" opt; do
    case "$opt" in
        t) ip="$OPTARG" ;;
        u) username="$OPTARG" ;;
        p) password="$OPTARG" ;;
        d) workgroup_domain="$OPTARG" ;;
        *) usage ;;
    esac
done

# Check if the IP variable is set
if [ -z "$ip" ]; then
    usage
fi

echo "
+---------------------------+
|         ROLL-CALL         |
|   Target enumeration v.3  |
+---------------------------+
"
# create main directory
mkdir -p $ip 2>/dev/null

# Create dashboard report
exec > >(tee $ip/REPORT.txt) 2>&1

# initial nmap scan
  mkdir -p $ip/port_scan 2>/dev/null
  echo -e "${ORANGE}[+] Starting nmap port/service scan:${NC}"
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
############################################################################################
############################################################################################
# nmap service scan #
############################################################################################
############################################################################################
echo -e "${ORANGE}[+] Starting service enumeration:${NC}"
for i in $ports
do
    sleep 1
    # list open ports in cli  
    sirs=$(cat $ip/port_scan/nmap_scan.txt | egrep open | egrep "tcp|udp" | egrep "^$i" )
    echo -e "${BLUE}[info] $sirs${NC}"
    services=$(cat $ip/port_scan/nmap_scan.txt | egrep "^[0-9]+++++"| egrep "$i" | awk '{print $3}')
    sleep 1


############################################################################################
############################################################################################
    # the bread and butter cycle #
############################################################################################
############################################################################################
    for service in $services; do 

        case $service in
            http|https|http?)
                # make http directory if found
                mkdir $ip/${i}_$service\_info 2>/dev/null
                echo -e "${ORANGE}[+] Starting http enumeration with gobuster/dirb/nikto/whatweb on Port: $i${NC}"
                sleep 1
                http_enumeration() {
                    # nikto for vulnerability scan
                    echo "COMMAND: nikto -h http://$ip:$i -Tuning 5" > $ip/${i}_http_info/nikto_scan.txt
                    echo -e "\n\n\n" >> $ip/${i}_http_info/nikto_scan.txt
                    nicky=$(nikto -h http://$ip:$i -Tuning 5 >> $ip/${i}_http_info/nikto_scan.txt 2>/dev/null)
                    # whatweb for vulnerability scan
                    echo "COMMAND: whatweb http://$ip:$i " > $ip/${i}_http_info/whatweb_scan.txt
                    echo -e "\n\n\n" >> $ip/${i}_http_info/whatweb_scan.txt
                    whatwebber=$(whatweb http://$ip:$i >> $ip/${i}_http_info/whatweb_scan.txt 2>/dev/null)
                    # gobuster for directories
                    echo "COMMAND: gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -q" > $ip/${i}_http_info/gobuster_directories.txt
                    echo -e "\n\n\n" >> $ip/${i}_http_info/gobuster_directories.txt
                    gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -q >> $ip/${i}_http_info/gobuster_directories.txt
                    # gobuster for files
                    echo "COMMAND: gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -q " > $ip/${i}_http_info/gobuster_files.txt
                    echo -e "\n\n\n" >> $ip/${i}_http_info/gobuster_files.txt
                    gobuster dir -u http://$ip:$i -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -q >> $ip/${i}_http_info/gobuster_files.txt
                    # dirb for directories
                    echo "COMMAND: dirb http://$ip:$i /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt" > $ip/${i}_http_info/dirb_directories.txt
                    echo -e "\n\n\n" >> $ip/${i}_http_info/dirb_directories.txt
                    dirbdir=$(dirb http://$ip:$i /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt >> $ip/${i}_http_info/dirb_directories.txt)
                    # dirb for files
                    echo "COMMAND: dirb http://$ip:$i /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt" > $ip/${i}_http_info/dirb_files.txt
                    echo -e "\n\n\n" >> $ip/${i}_http_info/dirb_files.txt
                    dirbfile=$(dirb http://$ip:$i /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt >> $ip/${i}_http_info/dirb_files.txt)
                }
                    http_enumeration &    
                ;;
            ftp|ftp?)
                mkdir $ip/${i}_$service\_info 2>/dev/null
                echo -e "${ORANGE}[+] Starting FTP enumeration on Port: $i${NC}"
                # test anon
                echo "COMMAND: hydra -l anonymous -p anonymous ftp://$ip -V -s $i" > $ip/${i}_ftp_info/anon_ftp_${i}.txt
                echo -e "\n\n\n" >> $ip/${i}_ftp_info/anon_ftp_${i}.txt
                hydra -u anonymous -p anonymous ftp://$ip -V -s $i 2>/dev/null >> $ip/${i}_ftp_info/anon_ftp_${i}.txt &
                sleep 1
                # test usernames and passwords
                if [[ -n "$username" && -n "$password" ]]; then
                    echo "COMMAND: hydra -l $username -p $password ftp://$ip:$i" > $ip/${i}_ftp_info/ftp_${i}.txt 
                    echo -e "\n\n\n" >> $ip/${i}_ftp_info/ftp_${i}.txt 
                    hydra -l $username -p $password ftp://$ip:$i 2>/dev/null  >> $ip/${i}_ftp_info/ftp_${i}.txt &
                fi
            ;;
            smb|microsoft-ds|microsoft-ds?)
                mkdir $ip/${i}_$service\_info 2>/dev/null
                sleep 1
                # if username and password are present, use them
                if [[ -n "$username" && -n "$password" ]]; then
                    echo -e "${ORANGE}[+] Starting SMB enumeration on Port: $i${NC}"
                    echo "COMMAND: enum4linux -v -u $username -p $password $ip" >  $ip/${i}_$service\_info/enum4linux_results_${i}.txt
                    echo -e "\n\n\n" >> $ip/${i}_$service\_info/enum4linux_results_${i}.txt
                    enum4linux -v $ip -u $username -p $password 2>/dev/null >> $ip/${i}_$service\_info/enum4linux_results_${i}.txt &
                    sleep 1
                    echo "COMMAND: smbclient -N -L \\\\$ip -U $username%$password" >  $ip/${i}_$service\_info/smbclient_results_${i}.txt
                    echo -e "\n\n\n" >> $ip/${i}_$service\_info/smbclient_results_${i}.txt
                    smbclient -N -L \\\\$ip -U $username%$password >> $ip/${i}_$service\_info/smbclient_results_${i}.txt 2>&1 &
                else
                # no username/password only checks with anon or default settings
                    echo -e "${ORANGE}[+] Starting SMB enumeration on Port: $i${NC}"
                    echo "COMMAND: enum4linux -v $ip" >  $ip/${i}_$service\_info/enum4linux_results_${i}.txt
                    echo -e "\n\n\n" >> $ip/${i}_$service\_info/enum4linux_results_${i}.txt
                    enum4linux $ip 2>/dev/null >> $ip/${i}_$service\_info/enum4linux_results_${i}.txt &
                    sleep 1
                    echo "COMMAND: smbclient -N -L \\\\$ip " >  $ip/${i}_$service\_info/smbclient_results_${i}.txt
                    echo -e "\n\n\n" >> $ip/${i}_$service\_info/smbclient_results_${i}.txt
                    smbclient -N -L \\\\$ip >> $ip/${i}_$service\_info/smbclient_results_${i}.txt 2>&1 &
                fi
                sleep 1
                ;;
            ssh|ssh?)
                # only run if creds are provided
                if [[ -n "$username" && -n "$password" ]]; then
                    mkdir $ip/${i}_$service\_info 2>/dev/null
                    echo "COMMAND: sshpass -p '$password' ssh -p $i -o StrictHostKeyChecking=no $username@$ip 'whoami;pwd;dir'" > $ip/${i}_$service\_info/ssh_results_${i}.txt
                    echo -e "\n\n\n" >> $ip/${i}_$service\_info/ssh_results_${i}.txt
                    sshpass -p "$password" ssh -p $i -o StrictHostKeyChecking=no $username@$ip 'whoami;pwd;dir' 2>/dev/null >> $ip/${i}_$service\_info/ssh_results_${i}.txt
                fi
                ;;
            dns|dns?)
                # mkdir $ip/${i}_$service\_info
                # to be added
                ;;
            rpc|msrpc|msrpc?)
                mkdir $ip/${i}_$service\_info 2>/dev/null
                sleep 1
                # test anonymous connect
                echo -e "${ORANGE}[+] Starting RPC enumeration: ${NC}"
                echo "COMMAND: rpcclient -U '' -N $ip -c enumdomusers" > $ip/${i}_$service\_info/rpcclient_anon_enum.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/rpcclient_anon_enum.txt
                rpc_test=$(rpcclient -U '' -N $ip -c enumdomusers >> $ip/${i}_$service\_info/rpcclient_anon_enum.txt 2>&1 &)
                sleep 1
                # test username and password
                if [[ -n "$username" && -n "$password" ]]; then
                    echo -e "${ORANGE}[+] Starting RPC enumeration: ${NC}"
                    echo "COMMAND: rpcclient -U $username -P $password $ip -c enumdomusers" > $ip/${i}_$service\_info/rpcclient_userpass_enum.txt
                    echo -e "\n\n\n" >> $ip/${i}_$service\_info/rpcclient_userpass_enum.txt
                    rpc_test=$(rpcclient -U "$username" -P "$password" "$ip" -c enumdomusers >> $ip/${i}_$service\_info/rpcclient_userpass_enum.txt 2>&1 &)
                    sleep 1
                fi
                # test username and password and domain
                if [[ -n "$username" && -n "$password" && -n "$workgroup_domain" ]]; then
                    echo -e "${ORANGE}[+] Starting RPC enumeration: ${NC}"
                    echo -e "\n\n\n" >> $ip/${i}_$service\_info/rpcclient_domain_enum.txt
                    rpc_func() {
                        # Define group type for enumalsgroups
                        grouptype="domain"  # Set this to "domain" or "builtin"
                        # Define known username for lookupnames
                        known_username="user1"  # Replace this with a valid username
                        # Step 1: Enumerate domain users and extract RIDs
                        user_rids=()
                        enum_users_output=$(rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c 'enumdomusers' 2>&1)
                        # Extract RIDs from the output
                        while IFS= read -r line; do
                            if [[ "$line" =~ \[([0-9]+)\] ]]; then
                                user_rids+=("${BASH_REMATCH[1]}")
                            fi
                        done <<< "$enum_users_output"
                        # Step 2: Use extracted RIDs to look up SIDs
                        for rid in "${user_rids[@]}"; do
                            lookup_output=$(rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c "queryuser $rid 1" 2>&1)
                            echo "Lookup result for RID $rid:"
                            echo "$lookup_output"
                        done
                        # Step 3: Extract domain SID and use it for lookups
                        lsa_output=$(rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c 'lsaquery' 2>&1)
                        if [[ "$lsa_output" =~ Domain\ SID:\ (S-[0-9\-]+) ]]; then
                            domain_sid="${BASH_REMATCH[1]}"
                            echo "Extracted Domain SID: $domain_sid"
                        fi
                        # Step 4: Construct full SIDs and look up names
                        if [[ -n "$domain_sid" ]]; then
                            for rid in "${user_rids[@]}"; do
                                full_sid="$domain_sid-$rid"
                                lookup_sid_output=$(rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c "lookupsids $full_sid" 2>&1)
                                echo "Lookup result for SID $full_sid:"
                                echo "$lookup_sid_output"
                            done
                        fi
                        rpcclient -W "$workgroup_domain" -U "$username" -P "$password" "$ip" -c enumdomusers
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c 'lsaquery' 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" -c 'srvinfo' "$ip" 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c "getdompwinfo" 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c "enumalsgroups $grouptype" 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c "enumdomgroups" 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c "lookupnames $known_username" 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c 'lsaenumsid' 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c "lookupsids $sid-$rid" 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c 'querydispinfo' 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c 'enumdomusers' 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c "querygroup $rid 1" 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c "queryuser $rid 1" 2>&1
                        rpcclient -W "$workgroup_domain" -U"$username%$password" "$ip" -c 'enumprinters' 2>&1
                    }
                    rpc_func >> $ip/${i}_$service\_info/rpcclient_domain_enum.txt 2>&1 &
                    sleep 1
                fi
                ;;
            netbios|netbios-ssn|netbios-ssn?|netbios?)
                mkdir $ip/${i}_$service\_info 2>/dev/null
                sleep 1
                echo -e "${ORANGE}[+] Starting NETBIOS enumeration on Port: $i${NC}"
                echo "[COMMAND] nbtscan $ip"
                echo "COMMAND: nbtscan $ip" > $ip/${i}_$service\_info/nbtscan_results.txt
                echo -e "\n\n\n" >> $ip/${i}_$service\_info/nbtscan_results.txt
                netbios_test=$(nbtscan $ip >> $ip/${i}_$service\_info/nbtscan_results.txt &)
                sleep 1
                ;;
            smtp|smtp?|mail)
                mkdir $ip/${i}_$service\_info 2>/dev/null
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
############################################################################################
# PROCESS CHECK
############################################################################################
############################################################################################
# Function to count active processes
count_active_processes() {
    # Get counts of different processes
    hydra_count=$(ps aux | egrep -w 'hydra' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    gobuster_count=$(ps aux | egrep -w 'gobuster' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    dirb_count=$(ps aux | egrep -w 'dirb' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    nikto_count=$(ps aux | egrep -w 'nikto' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    whatweb_count=$(ps aux | grep -w 'whatweb' | egrep -v 'color=auto' | egrep -v 'grep' | wc -l)
    enum4linux_count=$(ps aux | egrep -w 'enum4linux' | egrep -v "color=auto" | egrep -v "grep" | wc -l)
    rpc_count=$(ps aux | egrep -w 'rcpclient'| egrep -v "color=auto" | egrep -v "grep" | wc -l)
    netbios_count=$(ps aux | egrep -w 'nbtscan'| egrep -v "color=auto" | egrep -v "grep" | wc -l)
    smbclient_count=$(ps aux | egrep -w 'smbclient '| egrep -v "color=auto" | egrep -v "grep" | wc -l)
    smtp_enumusers_count=$(ps aux | egrep -w 'nmap -p 25 --script=smtp-enum-users' | egrep -v "color=auto" | egrep -v "grep" | wc -l )

    total_processes_count=$(($smtp_enumusers_count + $whatweb_count + $ftpcrack_count + $hydra_count + $gobuster_count + $dirb_count + $nikto_count + $enum4linux_count + $rpc_count + $netbios_count + $smbclient_count))
    echo $total_processes_count
}

# Check for user input while background tasks are running
echo -e "${YELLOW}[+] Waiting on the background scans to finish. Press the ENTER/RETURN key to check progress.${NC}"
active_processes=$(count_active_processes)
echo -e "${PINK}[WAIT] Active Enumeration Processes: $active_processes${NC}"
# Loop to monitor processes
while true; do
    # Wait for a keypress without blocking other tasks
    if read -t 1 -n 1; then
        # If a key was pressed, count active processes and display
        echo -e "${YELLOW}[+] Waiting on the background scans to finish. Press the ENTER/RETURN key to check progress.${NC}"
        active_processes=$(count_active_processes)
        echo -e "${PINK}[WAIT] Active Enumeration Processes: $active_processes${NC}"
    fi

    # Check if all processes have finished
    active_processes=$(count_active_processes)
    if [ "$active_processes" -eq 0 ]; then
        break
    fi

done

echo -e "${BLUE}[+] Enumeration complete.${NC}"


############################################################################################
############################################################################################
# useful info gathered
############################################################################################
############################################################################################
echo -e "${ORANGE}[+] Information gathered:${NC}"
for i in $ports
do
    sirs=$(cat $ip/port_scan/nmap_scan.txt | egrep open | egrep "tcp|udp" | egrep "^$i" )
    services=$(cat $ip/port_scan/nmap_scan.txt | egrep "^[0-9]+++++"| egrep "$i" | awk '{print $3}')
    
    # loop through each service to dump possible useful info found
    for service in $services; do 
    
        case $service in
                http|https|http?)
                    sleep 1
                    # gobuster for directories
                    echo -e "${GREEN}[+] Possible useful info found for gobuster http on port ${i}:${NC}"
                    egrep "\(Status:" $ip/${i}_http_info/gobuster_directories.txt
                    egrep "\(Status:" $ip/${i}_http_info/gobuster_files.txt
                    echo -e "${GREEN}[+] Possible useful info found for dirb http on port ${i}:${NC}"
                    egrep '\(CODE:[0-9]+' $ip/${i}_http_info/dirb_directories.txt
                    egrep '\(CODE:[0-9]+' $ip/${i}_http_info/dirb_files.txt
                    ;;
                ftp|ftp?)
                    sleep 1
                    results=$(egrep "^\[${i}\]" $ip/${i}_ftp_info/anon_ftp_${i}.txt 2>/dev/null)
                    if [ -n "$results" ]
                    then
                        echo -e "${GREEN}[+] Possible useful info found for FTP:${NC}"
                        echo $results
                    fi
                    results=$(egrep "^\[${i}\]" $ip/${i}_ftp_info/ftp_${i}.txt 2>/dev/null)
                    if [ -n "$results" ]
                    then
                        echo -e "${GREEN}[+] Possible useful info found for FTP:${NC}"
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
                    results=$(cat $ip/${i}_$service\_info/ssh_results_${i}.txt 2>/dev/null)
                    if [ -n "$results" ]
                    then
                        echo -e "${GREEN}[+] Possible useful info found for SSH:${NC}"
                        tail -n+6 $ip/${i}_$service\_info/ssh_results_${i}.txt 
                    fi                    
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

echo -e "${PINK}[COMPLETE] Roll-Call ${NC}"
