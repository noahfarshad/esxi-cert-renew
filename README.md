# ESXi host certificates, renewed through vCenter

Renew ESXi host certificates from PowerShell, one host at a time, plan by default. With vCenter in its default vmca mode, a host whose certificate expires within 30 days gets a new VMCA-signed certificate, the same Renew the vSphere Client offers. With vCenter in custom mode, each host writes its own CSR and keeps the private key, your CA signs it, and the next run checks the signed certificate and installs it. Every change is verified before the next host is touched, and the run stops at the first host that does not come back right.

License: GPL-3.0. Built for [essential.coach](https://essential.coach).
Full write-up: [Every Host Expires the Same Week](https://essential.coach/esxi-host-certificates-expire-the-same-week/)

**Where it stands:** 1.0.0 has been rehearsed, not yet run on a production vCenter. The rehearsal is 66 built-in checks and 68 end-to-end checks against a vCenter simulator that fails the way Broadcom's knowledge base says vCenter and ESXi fail; the simulator is in [`bench/`](bench/). On your vCenter, read the plan first, then commit one host with `-VMHost`.

## Why a script

VMCA host certificates last five years, so hosts that were added to vCenter in the same build expire in the same week. The vSphere Client renews one host at a time and says nothing about the cases that waste a maintenance window:

- A renewal on a host in maintenance mode finishes as a successful task and leaves the old certificate in place (KB 390133).
- A VMCA certificate cannot outlast VMCA's own CA certificate. When the VMCA root is near its end, Renew completes and the host's certificate still expires when the root does (KB 416914, KB 419417).
- In vmca mode a renewal replaces whatever the host has, including a certificate your own CA issued.
- With your own CA, the certificate has to carry the exact name vCenter uses for the host, chain to a CA vCenter already trusts, and match the key from the CSR the host generated last. Get one of those wrong and the host disconnects, or the import fails with "Cannot change the host configuration" (KB 397317).

This script reads every host first, says what it will do and why, refuses the cases above, and checks the result of each change.

## Run

```powershell
.\Update-EsxiCertificate.ps1 -SelfTest                                          # 66 checks of the certificate and decision logic, no vCenter needed
.\Update-EsxiCertificate.ps1 -Server vcsa01.example.com                         # plan: every host, its certificate and what it needs
.\Update-EsxiCertificate.ps1 -Server vcsa01.example.com -VMHost esx01.example.com -Commit   # one host first
.\Update-EsxiCertificate.ps1 -Server vcsa01.example.com -Cluster cl01 -Commit
.\Update-EsxiCertificate.ps1 -Server vcsa01.example.com -Days 90                # what expires within 90 days (default 30)
.\Update-EsxiCertificate.ps1 -Server vcsa01.example.com -Cluster cl01 -All -Commit         # every host in cl01, whatever its expiry
.\Update-EsxiCertificate.ps1 -Server vcsa01.example.com -PassThru | Export-Csv esxi-certs.csv -NoTypeInformation
```

Login goes through PowerCLI: `-Credential (Get-Credential)`, an existing `Connect-VIServer` session to the same server, or Windows pass-through. Without `-Commit` nothing is changed. `-VMHost` and `-Cluster` take wildcards.

A plan looks like this:

```
esxi-cert-renew 1.0.0  vCenter vcsa01.example.com (8.0.3), certificate mode vmca
renew certificates that expire within 30 days; plan only: nothing is changed (add -Commit)

HOST               CLUSTER  EXPIRES      DAYS  ISSUER                PLAN
esx01.example.com  cl01     2026-12-07     20  VMCA                  WOULD renew through VMCA: 20 days left
esx02.example.com  cl01     2029-05-05    900  VMCA                  ok, 900 days left
esx03.example.com  cl01     2026-11-27     10  VMCA                  SKIP: 10 days left, but in maintenance mode, where vCenter does not renew: exit maintenance mode and run again
esx04.example.com  cl01     2026-12-02     15  VMCA                  WOULD renew through VMCA: 15 days left
esx05.example.com  cl02     2026-12-12     25  Example Issuing CA 1  SKIP: 25 days left, but issued by 'Example Issuing CA 1', not VMCA, and a renewal in vmca mode would replace it. To keep CA certificates use custom mode; if that is your VMCA, add -VmcaIssuer (README)
esx06.example.com  cl02     2026-11-22      5  VMCA                  SKIP: not connected (disconnected): reconnect it first
esx07.example.com  cl02     2026-12-27     40  VMCA                  ok, 40 days left
esx09.example.com  cl02     2027-01-06     50  VMCA                  ok, 50 days left
esx08.example.com           2028-10-17    700  VMCA                  ok, 700 days left

2 host(s) to change. Run again with -Commit.
```

And `-Cluster cl01 -Commit`:

```
  esx01.example.com: refreshing CA certificates
  esx01.example.com: renewing through VMCA
  esx01.example.com: done: expires 2031-11-16, issued by VMCA; port 443 serves it
  esx04.example.com: refreshing CA certificates
  esx04.example.com: renewing through VMCA
  esx04.example.com: done: expires 2031-11-16, issued by VMCA; port 443 serves it

2 certificate(s) replaced and verified.
```

"Done" means three things were true: the host is connected again, vCenter shows the new certificate, and port 443 on the host serves it. When this machine cannot reach port 443 on the host, the line says so instead. The exit code is 1 when a host failed.

## vmca mode, the default

vCenter's own CA (VMCA) issues the host certificates. For each host that is due, the script:

1. Re-reads the host. It must still be connected, out of maintenance mode, and on the certificate the plan saw.
2. Refreshes the host's CA certificates from vCenter (Renew does this anyway, KB 426775) and reads the expiry of VMCA's CA certificate from that list. If a renewal could not get the host's certificate past that date and out of the `-Days` window, it stops here and changes nothing (KB 419417).
3. Renews through vCenter (`CertificateManager.CertMgrRefreshCertificates_Task`, the Renew button).
4. Waits up to 5 minutes for the host to be connected and show a new certificate. A host can read "Not responding" for a moment while its agents pick up the new certificate (KB 420313).
5. Checks that the new certificate expires later than the old one, and that port 443 serves it.

A host whose certificate came from another CA is never renewed in vmca mode, because vmca mode would replace it with a VMCA certificate. VMCA's CA certificate is recognised by its default name, `CN=CA, OU=VMware Engineering`. If yours was regenerated under another name, or VMCA is a subordinate CA, the plan names the issuer it did not recognise, and `-VmcaIssuer '<that name>'` tells the script it is VMCA.

Renewal works with lockdown mode on (KB 434360). A host that is already disconnected is left alone: reconnect it first. vCenter renews a VMCA certificate that has expired when the host reconnects.

## custom mode, your own CA

For an organization that issues host certificates from its own CA (a DoD or enterprise PKI). Needs vCenter and ESXi 8.0 Update 3 or later, the release where the vSphere Client gained the same CSR-and-import workflow (KB 409674). Older hosts are reported and left alone.

One-time setup, in this order:

```powershell
# 1. vCenter trusts your CA: the root and every issuing CA
Add-VITrustedCertificate -VCenterOnly -PemCertificateOrChain (Get-Content .\ca-chain.pem -Raw)

# 2. vCenter leaves host certificates to you (the value is lower case)
Get-AdvancedSetting -Entity $global:DefaultVIServer -Name vpxd.certmgmt.mode | Set-AdvancedSetting -Value custom -Confirm:$false
```

The same two steps are in the vSphere Client: Administration > Certificates > Certificate Management > Trusted Root Certificates > Add, then vCenter > Configure > Advanced Settings > `vpxd.certmgmt.mode`. KB 317244 restarts vpxd after the change (`service-control --restart vpxd`); the 8.0 documentation does not ask for it. The first line of the plan shows the mode vCenter reports. Going back from custom to vmca means removing every host from vCenter and adding it back, so treat the switch as a decision, not a toggle.

Then each round is the same command, twice:

```powershell
# First run: each host that is due, or still on a VMCA certificate, writes a CSR into the folder
.\Update-EsxiCertificate.ps1 -Server vcsa01.example.com -CertFolder .\certs -Days 90 -Commit

# Have each <host>.csr signed with a server-authentication template, and save the
# certificate next to it as <host>.crt. With a Microsoft CA:
certreq -submit -config "ca01.example.com\Example Issuing CA 1" -attrib "CertificateTemplate:WebServer" .\certs\esx01.example.com.csr .\certs\esx01.example.com.crt

# Second run: checks every signed certificate and installs the good ones
.\Update-EsxiCertificate.ps1 -Server vcsa01.example.com -CertFolder .\certs -Days 90 -Commit
```

`-Days 90` leaves time for the CA round trip. To set the organization fields of the CSR, add all five to the first run: `-Subject 'C=US, ST=Virginia, L=Reston, O=Example, OU=Infrastructure'`. The host name becomes the CN.

The signed certificate can be `.crt`, `.cer`, `.pem` or `.p7b`, in PEM or DER, alone or with its chain. A Microsoft CA's "certificate chain" download works as it comes.

The private key never leaves the host: the host generates it with the CSR and keeps it until the signed certificate is installed. Writing a CSR replaces any CSR the host made earlier, in the vSphere Client too, and the host then refuses a certificate signed from the earlier one. So the script writes a host's CSR only when the folder has none for it, and installs only certificates for CSRs it wrote. One folder holds one round. For the next round, start a new folder.

Before installing, the script refuses a certificate when:

- it was not issued for the key in the host's CSR
- its common name or Subject Alternative Name is not the name vCenter uses for the host
- the host calls itself by another name than vCenter does (KB 397317)
- it is a wildcard, a CA certificate or self-signed, is signed with SHA-1, MD5 or RSASSA-PSS, is not valid yet, or expires within `-Days`
- its key usage lacks Digital Signature or Key Encipherment, or its extended key usage lacks server authentication
- vCenter does not trust its issuing CA and root

Then it refreshes CA certificates from vCenter on every connected host in the cluster that does not list the new chain yet. vSphere HA and vSAN hosts check each other's certificates, so every host has to trust the new CA before any host starts using it. The script installs the certificate (`HostCertificateManager.InstallServerCertificate`), tells the host's services to use it (`NotifyAffectedServices`, ESXi 8.0 Update 3 and later), and waits for vCenter to show it. Those are the two calls PowerCLI's own `Set-VIMachineCertificate` makes.

For hosts in a vSAN cluster, Broadcom's documentation points to KB 317244, a procedure with maintenance mode and a reboot per host that predates the 8.0 Update 3 workflow. This script handles the trust order behind that procedure, but it has not been run on a vSAN cluster. Do the first host there in a window.

## Straight to an ESXi host

With `-Server` pointing at an ESXi host that no vCenter manages, the custom workflow above runs against that host alone. A host that a vCenter manages is reported and left alone: run against its vCenter instead, or vCenter would lose trust in it.

## Requirements

- PowerShell 7, or Windows PowerShell 5.1 with .NET Framework 4.7.2 or later
- VCF.PowerCLI 9, or VMware.PowerCLI 13.3 or later (`Install-Module VCF.PowerCLI`)
- vmca mode: vCenter 7.0 or later. custom mode: vCenter and ESXi 8.0 Update 3 or later
- An account with Certificates > Manage certificates (`Certificate.Manage`) on the hosts
- Optional: this machine can reach port 443 on the hosts, for the final check

Windows marks a script downloaded from the web and PowerShell then declines to run it: `Unblock-File .\Update-EsxiCertificate.ps1` clears the mark, and a `git clone` never sets it.

If PowerCLI refuses vCenter's own certificate, trust vCenter's root on this machine (`https://<vcenter>/certs/download.zip`) rather than turning the check off.

## What it does not do

- Switch the certificate mode, or add CAs to vCenter's trusted roots. Both are decisions about who vouches for the hosts, and they come before the first run.
- Renew the VMCA root. When that is the limit, it says so: KB 419417 covers the vCert utility that does it.
- Thumbprint mode. vCenter does not manage host certificates there, and the plan says so.
- Replace VCF's own certificate management. Where SDDC Manager or VCF Operations manages ESXi certificates, use that workflow: it keeps track of what it issued.

## Tests

`-SelfTest` builds a small PKI in memory and runs 66 checks of the parsing, the certificate checks and every decision branch. It needs no vCenter and changes nothing.

[`bench/e2e.sh`](bench/) runs the script end to end, 68 checks, against `certsim`: govmomi's vCenter simulator plus the certificate calls it lacks, written to behave the way the API reference and the KBs below describe. The hosts have names, serve their certificates on port 443, go "Not responding" after a renewal, refuse a certificate for a superseded CSR, and disconnect when vCenter does not trust what they were given. Every refusal and every failure in this README happens there at least once.

A simulator proves the script's logic and its handling of documented behaviour. It does not prove vCenter. The script has not yet run against a production vCenter, and Windows PowerShell 5.1 has been checked by analyzer profile, not run.

## Broadcom knowledge base

| KB | What it says |
|----|--------------|
| 385183 | Renew ESXi host certificates with VMCA: Configure > System > Certificate > Renew |
| 390133 | A renewal in maintenance mode completes and changes nothing |
| 416914, 419417 | A VMCA renewal cannot outlast VMCA's root; renew the root first |
| 426775 | Renew versus Refresh CA Certificates |
| 420313 | A host can read "Not responding" for a moment after a renewal |
| 434360 | Renewal works with lockdown mode on |
| 383320, 410036 | Custom mode: CSR and Import and Replace from the vSphere Client, 8.0 U3 and later |
| 409674 | The external CA workflow is not in 8.0 U2 and earlier |
| 397317 | Import fails when the certificate name is not the host's own name |
| 317244 | Custom certificates from the ESXi shell, the procedure for vSAN clusters |
