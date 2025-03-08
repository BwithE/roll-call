#!/bin/bash

# Define dependent programs
DEPENDENT_PROGRAMS=("nmblookup" "net" "smbclient")

# Check if the dependent programs are installed
for prog in "${DEPENDENT_PROGRAMS[@]}"; do
    if ! command -v "$prog" &> /dev/null; then
        echo "Error: $prog is not installed." >&2
        exit 1
    fi
done

# Define function to print a success message
print_plus() {
    echo -e "\e[32m$1\e[0m"
}

# Define function to print an error message
print_error() {
    echo -e "\e[31m$1\e[0m"
}

# Parse command-line arguments
workgroup_domain="$1"
username="$2"
password="$3"
target_ip="$4"

# Define group type for enumalsgroups
grouptype="domain"  # Set this to "domain" or "builtin"

# Define known username for lookupnames
known_username="user1"  # Replace this with a valid username

# Step 1: Enumerate domain users and extract RIDs
user_rids=()
enum_users_output=$(rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c 'enumdomusers' 2>&1)

# Extract RIDs from the output
while IFS= read -r line; do
    if [[ "$line" =~ \[([0-9]+)\] ]]; then
        user_rids+=("${BASH_REMATCH[1]}")
    fi
done <<< "$enum_users_output"

# Step 2: Use extracted RIDs to look up SIDs
for rid in "${user_rids[@]}"; do
    lookup_output=$(rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c "queryuser $rid 1" 2>&1)
    echo "Lookup result for RID $rid:"
    echo "$lookup_output"
done

# Step 3: Extract domain SID and use it for lookups
lsa_output=$(rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c 'lsaquery' 2>&1)

if [[ "$lsa_output" =~ Domain\ SID:\ (S-[0-9\-]+) ]]; then
    domain_sid="${BASH_REMATCH[1]}"
    echo "Extracted Domain SID: $domain_sid"
fi

# Step 4: Construct full SIDs and look up names
if [[ -n "$domain_sid" ]]; then
    for rid in "${user_rids[@]}"; do
        full_sid="$domain_sid-$rid"
        lookup_sid_output=$(rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c "lookupsids $full_sid" 2>&1)
        echo "Lookup result for SID $full_sid:"
        echo "$lookup_sid_output"
    done
fi

# Additional rpcclient commands
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c 'lsaquery' 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" -c 'srvinfo' "$target_ip" 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c "getdompwinfo" 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c "enumalsgroups $grouptype" 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c "enumdomgroups" 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c "lookupnames $known_username" 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c 'lsaenumsid' 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c "lookupsids $sid-$rid" 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c 'querydispinfo' 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c 'enumdomusers' 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c "querygroup $rid 1" 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c "queryuser $rid 1" 2>&1
rpcclient -W "$workgroup_domain" -U"$username%$password" "$target_ip" -c 'enumprinters' 2>&1
