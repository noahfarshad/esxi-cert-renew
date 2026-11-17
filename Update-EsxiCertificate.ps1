#Requires -Version 5.1

<#
.SYNOPSIS
    Renew ESXi host certificates through vCenter, one host at a time. Plan by default.

.DESCRIPTION
    Reads every host's certificate, decides what each one needs and prints the plan.
    Nothing changes until you add -Commit.

    vCenter in vmca mode (the default): a host whose certificate expires within -Days
    gets a new VMCA-signed certificate, the vSphere Client's Renew.

    vCenter in custom mode (your own CA): the host writes a CSR and keeps the private
    key. The CSR lands in -CertFolder, your CA signs it, you drop the certificate next to
    it, and the next run checks it and installs it. Needs vCenter and ESXi 8.0 Update 3
    or later, the release where the vSphere Client gained the same workflow.

    Connected straight to an ESXi host that no vCenter manages, only the custom workflow
    applies.

    Every change is verified: the host is connected again, vCenter shows the new
    certificate, and port 443 serves it when this machine can reach the host. The run
    stops at the first host that does not come back right.

.PARAMETER Server
    The vCenter Server, or an ESXi host that no vCenter manages.

.PARAMETER Credential
    Login for -Server. Without it Connect-VIServer uses an existing session, Windows
    pass-through or asks.

.PARAMETER Cluster
    Only hosts in these clusters. Wildcards work.

.PARAMETER VMHost
    Only these hosts, by their name in vCenter. Wildcards work.

.PARAMETER Days
    Renew a certificate that expires within this many days. Default 30, when vCenter
    raises its red alarm. With your own CA allow for the signing round trip: -Days 90.

.PARAMETER All
    Renew every host in scope, whatever its expiry date.

.PARAMETER CertFolder
    Custom mode: CSRs are written here as <host>.csr and signed certificates are read
    from here as <host>.crt, .cer, .pem or .p7b. One folder holds one round of certificates.

.PARAMETER Subject
    Custom mode: the organization fields of the CSR subject, all five of them:
    'C=US, ST=Virginia, L=Reston, O=Example, OU=Infrastructure'. The host name becomes
    the CN. Without -Subject the host fills in its own defaults.

.PARAMETER VmcaIssuer
    vmca mode: the common name of VMCA's CA certificate when it is not the default "CA",
    because the VMCA root was regenerated under another name or VMCA is a subordinate
    CA. The plan names any issuer it did not recognise.

.PARAMETER Commit
    Make the changes. Without it nothing is changed.

.PARAMETER PassThru
    Also return one object per host, for Export-Csv.

.PARAMETER SelfTest
    Run the built-in checks of the certificate and decision logic. Needs no vCenter.

.EXAMPLE
    .\Update-EsxiCertificate.ps1 -Server vcsa01.example.com
    Plan: every host, its certificate and what it needs. Changes nothing.

.EXAMPLE
    .\Update-EsxiCertificate.ps1 -Server vcsa01.example.com -Cluster cl01 -Commit
    vmca mode: renew the certificates in cl01 that expire within 30 days.

.EXAMPLE
    .\Update-EsxiCertificate.ps1 -Server vcsa01.example.com -CertFolder .\certs -Days 90 -Commit
    custom mode, first run: write a CSR for every host that expires within 90 days or
    is still on a VMCA certificate. Have them signed, put <host>.crt next to each CSR,
    then run the same line again to install them.

.LINK
    https://github.com/noahfarshad/esxi-cert-renew
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'An interactive report; -PassThru gives objects')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Internal helpers')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Justification = 'Each one falls back to a safe default')]
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $Server,

    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [string[]] $Cluster,

    [string[]] $VMHost,

    [ValidateRange(1, 3650)]
    [int] $Days = 30,

    [switch] $All,

    [string] $CertFolder,

    [string] $Subject,

    [string] $VmcaIssuer,

    [switch] $Commit,

    [switch] $PassThru,

    [switch] $SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolVersion = '1.0.0'
$script:TaskTimeout = 600       # seconds for a vCenter task
$script:SettleTimeout = 300     # seconds for a host to reconnect and show its new certificate
$script:ServeTimeout = 120      # seconds for port 443 to serve the new certificate
$script:ServePort = 443
$script:VmcaName = "$VmcaIssuer".Trim()
$script:CustomMinimum = [version]'8.0.3'
$script:DaysValid = 1825        # vpxd.certmgmt.certs.daysValid, read from vCenter
$script:SignedExtensions = @('.crt', '.cer', '.pem', '.p7b')
$script:WeakSignature = @{
    '1.2.840.113549.1.1.2'  = 'MD2'
    '1.2.840.113549.1.1.4'  = 'MD5'
    '1.2.840.113549.1.1.5'  = 'SHA-1'
    '1.3.14.3.2.29'         = 'SHA-1'
    '1.2.840.113549.1.1.10' = 'RSASSA-PSS'
    '1.2.840.10040.4.3'     = 'DSA with SHA-1'
    '1.2.840.10045.4.1'     = 'ECDSA with SHA-1'
}

# ---------------------------------------------------------------------------------------
# Certificates: parsing and checks. No vSphere here, so -SelfTest covers all of it.
# ---------------------------------------------------------------------------------------

function ConvertTo-X509 {
    param([byte[]] $Der)
    New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $Der)
}

function ConvertTo-X509List {
    # PEM with one or more certificates, one DER certificate, or PKCS#7 (.p7b) in either
    # form. A Microsoft CA's base-64 chain download is PKCS#7 inside CERTIFICATE lines.
    param([byte[]] $Bytes)
    $list = New-Object System.Collections.ArrayList
    $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
    $blocks = [regex]::Matches($text, '-----BEGIN (?:CERTIFICATE|PKCS7)-----([A-Za-z0-9+/=\s]+?)-----END (?:CERTIFICATE|PKCS7)-----')
    $ders = New-Object System.Collections.ArrayList
    if ($blocks.Count -gt 0) {
        foreach ($b in $blocks) { [void]$ders.Add([Convert]::FromBase64String(($b.Groups[1].Value -replace '\s', ''))) }
    }
    else { [void]$ders.Add($Bytes) }
    foreach ($der in $ders) {
        $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $col.Import([byte[]]$der)
        foreach ($c in $col) { [void]$list.Add($c) }
    }
    , $list.ToArray()
}

function ConvertFrom-HostCertificate {
    # HostSystem.config.certificate: PEM text as (s)bytes. $null when the host has none to show.
    param($Value)
    if ($null -eq $Value -or @($Value).Count -eq 0) { return $null }
    if ($Value -is [byte[]]) { $bytes = $Value }
    elseif ($Value -is [sbyte[]]) {
        $bytes = New-Object byte[] $Value.Length
        [System.Buffer]::BlockCopy($Value, 0, $bytes, 0, $Value.Length)
    }
    else { $bytes = [byte[]]@(foreach ($x in $Value) { [int]$x -band 0xFF }) }
    $certs = ConvertTo-X509List $bytes
    if ($certs.Count -eq 0) { return $null }
    $certs[0]
}

function Read-DerNode {
    param([byte[]] $Bytes, [int] $Offset)
    if ($Offset + 2 -gt $Bytes.Length) { throw 'truncated DER' }
    $tag = [int]$Bytes[$Offset]
    $i = $Offset + 1
    $len = [int]$Bytes[$i]; $i++
    if ($len -band 0x80) {
        $n = $len -band 0x7F
        if ($n -lt 1 -or $n -gt 3) { throw 'unsupported DER length' }
        $len = 0
        for ($k = 0; $k -lt $n; $k++) { $len = ($len * 256) + [int]$Bytes[$i]; $i++ }
    }
    if ($i + $len -gt $Bytes.Length) { throw 'truncated DER' }
    New-Object psobject -Property @{ Tag = $tag; Header = $Offset; Start = $i; End = $i + $len }
}

function Get-DerChild {
    param([byte[]] $Bytes, $Node)
    $kids = New-Object System.Collections.ArrayList
    $i = $Node.Start
    while ($i -lt $Node.End) {
        $c = Read-DerNode $Bytes $i
        [void]$kids.Add($c)
        $i = $c.End
    }
    , $kids.ToArray()
}

function Get-DerSlice {
    param([byte[]] $Bytes, [int] $From, [int] $To)
    $out = New-Object byte[] ($To - $From)
    [Array]::Copy($Bytes, $From, $out, 0, $To - $From)
    , $out
}

function Test-SameByte {
    param([byte[]] $A, [byte[]] $B)
    if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) { if ($A[$i] -ne $B[$i]) { return $false } }
    $true
}

function Get-GeneralName {
    # GeneralNames: DNS names [2] and IP addresses [7].
    param([byte[]] $Bytes)
    $dns = @(); $ip = @()
    $seq = Read-DerNode $Bytes 0
    foreach ($n in (Get-DerChild $Bytes $seq)) {
        $v = Get-DerSlice $Bytes $n.Start $n.End
        if ($n.Tag -eq 0x82) { $dns += [System.Text.Encoding]::ASCII.GetString($v) }
        elseif ($n.Tag -eq 0x87 -and ($v.Length -eq 4 -or $v.Length -eq 16)) { $ip += ([System.Net.IPAddress]::new($v)).ToString() }
    }
    New-Object psobject -Property @{ Dns = $dns; Ip = $ip }
}

function Get-SanName {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert)
    foreach ($e in $Cert.Extensions) {
        if ($e.Oid.Value -eq '2.5.29.17') { return (Get-GeneralName $e.RawData) }
    }
    New-Object psobject -Property @{ Dns = @(); Ip = @() }
}

function Get-CommonName {
    param([string] $Dn)
    $m = [regex]::Match($Dn, '(?:^|,\s*)CN=("(?:[^"]|"")*"|[^,+]*)')
    if (-not $m.Success) { return '' }
    $m.Groups[1].Value.Trim().Trim('"')
}

function Get-CertSpki {
    # The certificate's SubjectPublicKeyInfo, exactly as encoded.
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert)
    $b = $Cert.RawData
    $tbs = (Get-DerChild $b (Read-DerNode $b 0))[0]
    $f = Get-DerChild $b $tbs
    $at = 5
    if ($f[0].Tag -eq 0xA0) { $at = 6 }
    Get-DerSlice $b $f[$at].Header $f[$at].End
}

function Get-CsrInfo {
    # PKCS#10: subject, DNS/IP Subject Alternative Names and the public key.
    param([string] $Pem)
    $m = [regex]::Match($Pem, '-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----([A-Za-z0-9+/=\s]+?)-----END (?:NEW )?CERTIFICATE REQUEST-----')
    if (-not $m.Success) { throw 'not a PEM certificate request' }
    $b = [Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', ''))
    $info = (Get-DerChild $b (Read-DerNode $b 0))[0]
    $f = Get-DerChild $b $info
    $dn = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName -ArgumentList (, (Get-DerSlice $b $f[1].Header $f[1].End))
    $names = New-Object psobject -Property @{ Dns = @(); Ip = @() }
    if ($f.Count -gt 3 -and $f[3].Tag -eq 0xA0) {
        foreach ($attr in (Get-DerChild $b $f[3])) {
            $parts = Get-DerChild $b $attr
            if ([BitConverter]::ToString((Get-DerSlice $b $parts[0].Start $parts[0].End)) -ne '2A-86-48-86-F7-0D-01-09-0E') { continue }   # extensionRequest
            $exts = (Get-DerChild $b $parts[1])[0]
            foreach ($ext in (Get-DerChild $b $exts)) {
                $e = Get-DerChild $b $ext
                if ([BitConverter]::ToString((Get-DerSlice $b $e[0].Start $e[0].End)) -eq '55-1D-11') {                     # subjectAltName
                    $v = $e[$e.Count - 1]
                    $names = Get-GeneralName (Get-DerSlice $b $v.Start $v.End)
                }
            }
        }
    }
    New-Object psobject -Property @{
        Subject    = $dn.Name
        CommonName = Get-CommonName $dn.Name
        Dns        = $names.Dns
        Ip         = $names.Ip
        Spki       = (Get-DerSlice $b $f[2].Header $f[2].End)
    }
}

function Test-IsIp {
    param([string] $Name)
    if ($Name -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -and $Name -notmatch ':') { return $false }
    $ip = $null
    [System.Net.IPAddress]::TryParse($Name, [ref]$ip)
}

function Test-NameIn {
    # Is $Name among a certificate's DNS names, or its IP addresses when it is an address?
    param([string] $Name, $Dns, $Ip)
    if (Test-IsIp $Name) {
        $want = [System.Net.IPAddress]::Parse($Name)
        foreach ($i in @($Ip)) {
            $have = $null
            if ($i -and [System.Net.IPAddress]::TryParse("$i", [ref]$have) -and $have.Equals($want)) { return $true }
        }
        return $false
    }
    @($Dns | Where-Object { $_ -eq $Name }).Count -gt 0
}

function Test-VmcaIssuer {
    # VMCA's CA certificate is CN=CA, ..., OU=VMware Engineering by default. -VmcaIssuer
    # names it when the root was regenerated under another name or VMCA is a subordinate CA.
    param([string] $Dn)
    if ($script:VmcaName -and (Get-CommonName $Dn) -eq $script:VmcaName) { return $true }
    ($Dn -match '(?:^|,\s*)CN=CA(?:,|$)') -and ($Dn -match '(?:^|,\s*)OU=VMware Engineering(?:,|$)')
}

function Get-IssuerLabel {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert)
    if (Test-VmcaIssuer $Cert.Issuer) { return 'VMCA' }
    Get-CommonName $Cert.Issuer
}

function Get-VmcaEnd {
    # The latest expiry among the VMCA CA certificates on a CA list; $null when none is there.
    # A VMCA renewal cannot outlast it (KB 419417).
    param($CaList)
    $end = $null
    foreach ($c in @($CaList)) {
        if ($c -and (Test-VmcaIssuer $c.Subject) -and ($null -eq $end -or $c.NotAfter -gt $end)) { $end = $c.NotAfter }
    }
    $end
}

function Test-VmcaLimit {
    # Is VMCA's CA certificate, ending at $End, too short-lived for a renewal to help?
    # A renewed certificate ends when it does, so it has to end after the certificate
    # being replaced and outside the -Days window, or the host is due again at once.
    param([datetime] $End, [datetime] $OldEnd, [datetime] $Now, [int] $Days)
    ($End -le $OldEnd.AddDays(1)) -or ($End -le $Now.AddDays($Days))
}

function Get-LeafProblem {
    # Why a signed certificate must not be installed on host $Name. Empty when it is fine.
    param($Leaf, [string] $Name, $Csr, [datetime] $Now, [int] $Days)
    $p = @()
    if (-not (Test-SameByte (Get-CertSpki $Leaf) $Csr.Spki)) { $p += 'it was not issued for the CSR in the folder (the public key differs)' }
    foreach ($e in $Leaf.Extensions) {
        if ($e -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] -and $e.CertificateAuthority) { $p += 'it is a CA certificate' }
    }
    $san = Get-SanName $Leaf
    if (-not (Test-NameIn $Name $san.Dns $san.Ip)) { $p += "its Subject Alternative Name does not include $Name" }
    if (@($san.Dns | Where-Object { $_.StartsWith('*') }).Count -gt 0) { $p += 'it is a wildcard certificate, which vSphere does not accept' }
    $cn = Get-CommonName $Leaf.Subject
    if ($cn -ne $Name) { $p += "its common name is '$cn', not $Name" }
    if ($Leaf.NotBefore -gt $Now) { $p += "it is not valid before $(Format-Day $Leaf.NotBefore)" }
    if ($Leaf.NotAfter -le $Now.AddDays($Days)) { $p += "it expires $(Format-Day $Leaf.NotAfter), within $Days days" }
    $sig = $Leaf.SignatureAlgorithm.Value
    if ($script:WeakSignature.ContainsKey($sig)) { $p += "it is signed with $($script:WeakSignature[$sig]), which vSphere does not accept" }
    foreach ($e in $Leaf.Extensions) {
        if ($e -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $need = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature, KeyEncipherment'
            if (($e.KeyUsages -band $need) -ne $need) { $p += 'its key usage lacks Digital Signature or Key Encipherment' }
        }
        if ($e -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            $ekus = @(foreach ($u in $e.EnhancedKeyUsages) { $u.Value })
            if ($ekus -notcontains '1.3.6.1.5.5.7.3.1') { $p += 'its extended key usage does not include server authentication' }
        }
    }
    $p
}

function Get-ChainCheck {
    # Builds the chain from the leaf through the certificates in the file and the CA list
    # (on a host after "Refresh CA Certificates": vCenter's TRUSTED_ROOTS). Every CA
    # certificate in the chain must be on that list.
    param($Leaf, $Extra, $CaList, [datetime] $Now)
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
    $chain.ChainPolicy.VerificationTime = $Now
    if ($chain.ChainPolicy.PSObject.Properties['DisableCertificateDownloads']) { $chain.ChainPolicy.DisableCertificateDownloads = $true }
    else { $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(5) }
    foreach ($c in @($Extra) + @($CaList)) { if ($c) { [void]$chain.ChainPolicy.ExtraStore.Add($c) } }
    [void]$chain.Build($Leaf)
    $elements = @(foreach ($el in $chain.ChainElements) { $el })
    if ($elements.Count -eq 0) { return (New-Object psobject -Property @{ Problems = @('no certificate chain can be built from it'); Cas = @() }) }
    $problems = @()
    if ($elements.Count -eq 1 -and $Leaf.Subject -eq $Leaf.Issuer) { $problems += 'it is self-signed' }
    $cas = @()
    $listed = @{}
    foreach ($c in @($CaList)) { if ($c) { $listed[$c.Thumbprint] = $true } }
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $el = $elements[$i]
        foreach ($s in $el.ChainElementStatus) {
            if ($s.Status -eq 'NoError' -or $s.Status -eq 'UntrustedRoot') { continue }
            if ($s.Status -eq 'PartialChain') { continue }
            $problems += "$(Get-CommonName $el.Certificate.Subject): $($s.Status)"
        }
        if ($i -eq 0) { continue }
        $c = $el.Certificate
        $cas += $c
        if (-not $listed.ContainsKey($c.Thumbprint)) { $problems += "vCenter does not trust $(Get-CommonName $c.Subject) (not in its TRUSTED_ROOTS)" }
        if ($c.Subject -ne $c.Issuer -and $script:WeakSignature.ContainsKey($c.SignatureAlgorithm.Value)) {
            $problems += "$(Get-CommonName $c.Subject) is signed with $($script:WeakSignature[$c.SignatureAlgorithm.Value])"
        }
    }
    $last = $elements[$elements.Count - 1].Certificate
    if ($last.Subject -ne $last.Issuer) {
        $problems += "the certificate that issued $(Get-CommonName $last.Subject) ($(Get-CommonName $last.Issuer)) is neither in the file nor in vCenter's TRUSTED_ROOTS"
    }
    New-Object psobject -Property @{ Problems = @($problems | Select-Object -Unique); Cas = $cas }
}

function Format-Day {
    param([datetime] $When)
    $When.ToString('yyyy-MM-dd')
}

function ConvertTo-ApiVersion {
    param([string] $Text)
    $m = [regex]::Match("$Text", '^\d+(\.\d+){1,3}')
    if (-not $m.Success) { return [version]'0.0' }
    [version]$m.Value
}

function Get-OwnName {
    # The FQDN the host gives itself.
    param([string] $HostName, [string] $DomainName)
    if (-not $HostName) { return '' }
    if ($DomainName -and $HostName -notlike "*.$DomainName") { return "$HostName.$DomainName" }
    $HostName
}

function Get-SafeName {
    param([string] $Name)
    $Name -replace '[^A-Za-z0-9._-]', '_'
}

function ConvertTo-CsrDn {
    # -Subject plus the host name, in the form and order PowerCLI's own
    # New-VIMachineCertificateSigningRequest sends to the host.
    param([string] $Subject, [string] $Name)
    $have = @{}
    foreach ($part in ($Subject -split ',')) {
        $kv = @($part -split '=', 2)
        if ($kv.Count -ne 2 -or -not $kv[1].Trim()) { throw "-Subject: cannot read '$($part.Trim())'. Write it as C=US, ST=Virginia, L=Reston, O=Example, OU=Infrastructure." }
        $k = $kv[0].Trim().ToUpperInvariant()
        if ($k -eq 'S') { $k = 'ST' }
        if (@('C', 'ST', 'L', 'O', 'OU') -notcontains $k) { throw "-Subject: '$($kv[0].Trim())' is not one of C, ST, L, O, OU. The host name becomes the CN." }
        if ($have.ContainsKey($k)) { throw "-Subject: $k is there twice." }
        $have[$k] = $kv[1].Trim()
    }
    foreach ($k in 'C', 'ST', 'L', 'O', 'OU') { if (-not $have.ContainsKey($k)) { throw "-Subject needs all of C, ST, L, O and OU: $k is missing." } }
    if ($have['C'] -notmatch '^[A-Za-z]{2}$') { throw '-Subject: C is the two-letter country code, for example US.' }
    "CN = $Name, C = $($have['C'].ToUpperInvariant()), L = $($have['L']), ST = $($have['ST']), O = $($have['O']), OU = $($have['OU'])"
}

# ---------------------------------------------------------------------------------------
# Decisions: what each host needs. Pure, so -SelfTest covers it.
# ---------------------------------------------------------------------------------------

function Get-Decision {
    <#
    $H:   Name, Connected, State, Maintenance, Cert, NotAfter, IsVmca, Issuer, Api, ManagedBy, OwnName
    $Ctx: Mode (vmca|custom|thumbprint|standalone), Days, All, Now, VcApi, Folder (bool)
    $F:   folder state for custom work: Csr (info or $null), CsrPath, CsrError, Signed (X509[]
          or $null), SignedPath, SignedError, Leaf (matching the CSR or $null)
    Returns Action (none|renew|csr|wait|install|skip) and Reason.
    #>
    param($H, $Ctx, $F)
    $r = { param($a, $why) New-Object psobject -Property @{ Action = $a; Reason = $why } }
    if (-not $H.Cert) { return (& $r 'skip' 'cannot read its certificate') }
    if (-not $H.Connected) { return (& $r 'skip' "not connected ($($H.State)): reconnect it first") }
    $left = [int][Math]::Floor(($H.NotAfter - $Ctx.Now).TotalDays)
    $due = $Ctx.All -or ($H.NotAfter -le $Ctx.Now.AddDays($Ctx.Days))

    switch ($Ctx.Mode) {
        'thumbprint' {
            return (& $r 'none' 'thumbprint mode: vCenter does not manage host certificates')
        }
        'vmca' {
            if (-not $due) { return (& $r 'none' "ok, $left days left") }
            if (-not $H.IsVmca) {
                return (& $r 'skip' "$left days left, but issued by '$($H.Issuer)', not VMCA, and a renewal in vmca mode would replace it. To keep CA certificates use custom mode; if that is your VMCA, add -VmcaIssuer (README)")
            }
            if ($H.Maintenance) { return (& $r 'skip' "$left days left, but in maintenance mode, where vCenter does not renew: exit maintenance mode and run again") }
            return (& $r 'renew' "$left days left")
        }
        default {
            # custom (vCenter) or standalone (direct to ESXi)
            if ($Ctx.Mode -eq 'standalone' -and $H.ManagedBy) {
                return (& $r 'none' "managed by vCenter $($H.ManagedBy): run this against that vCenter")
            }
            $needs = $due -or ($Ctx.Mode -eq 'custom' -and $H.IsVmca)
            $nameOff = ''
            if ($H.OwnName -and -not (Test-IsIp $H.Name) -and $H.OwnName -ne $H.Name) {
                $nameOff = "the host calls itself $($H.OwnName) while vCenter knows it as $($H.Name), and ESXi refuses a certificate for a name that is not its own (KB 397317): make the two names match first"
            }
            $why = "$left days left"
            if ($Ctx.Mode -eq 'custom' -and $H.IsVmca) { $why = 'still on a VMCA certificate' }
            if (-not $Ctx.Folder) {
                if ($needs) { return (& $r 'none' "$($why): give -CertFolder to write its CSR") }
                return (& $r 'none' "ok, $left days left")
            }
            $tooOld = ''
            if ($Ctx.Mode -eq 'custom' -and $Ctx.VcApi -lt $script:CustomMinimum) { $tooOld = "vCenter $($Ctx.VcApi)" }
            if ($H.Api -lt $script:CustomMinimum) { $tooOld = "ESXi $($H.Api)" }
            $oldText = "$tooOld is older than 8.0 Update 3, which cannot take a certificate through the API without a restart (README)"
            if ($F.CsrError) { return (& $r 'skip' "cannot read $(Split-Path -Leaf $F.CsrPath): $($F.CsrError)") }
            if ($F.Signed -or $F.SignedError) {
                if ($F.SignedError) { return (& $r 'skip' "cannot read $(Split-Path -Leaf $F.SignedPath): $($F.SignedError)") }
                if (-not $F.Csr) { return (& $r 'skip' "$(Split-Path -Leaf $F.SignedPath) has no $(Split-Path -Leaf $F.CsrPath) next to it; this tool installs only certificates for CSRs it wrote") }
                if (-not $F.Leaf) { return (& $r 'skip' "$(Split-Path -Leaf $F.SignedPath) holds no certificate for the public key in $(Split-Path -Leaf $F.CsrPath)") }
                if ($F.Leaf.Thumbprint -eq $H.Cert.Thumbprint) {
                    if ($due) { return (& $r 'skip' "$left days left, and $(Split-Path -Leaf $F.SignedPath) is the certificate already installed: start the next round in a new -CertFolder") }
                    return (& $r 'none' "installed from $(Split-Path -Leaf $F.SignedPath), $left days left")
                }
                if ($tooOld) { return (& $r 'skip' $oldText) }
                if ($nameOff) { return (& $r 'skip' $nameOff) }
                return (& $r 'install' "$(Split-Path -Leaf $F.SignedPath), issued by $(Get-IssuerLabel $F.Leaf), expires $(Format-Day $F.Leaf.NotAfter)")
            }
            if ($F.Csr) { return (& $r 'wait' "for $(Get-SafeName $H.Name).crt, signed from $(Split-Path -Leaf $F.CsrPath)") }
            if (-not $needs) { return (& $r 'none' "ok, $left days left") }
            if ($tooOld) { return (& $r 'skip' "$($why), but $oldText") }
            if ($nameOff) { return (& $r 'skip' "$($why), but $nameOff") }
            return (& $r 'csr' $why)
        }
    }
}

function Get-FolderState {
    param([string] $Folder, [string] $Name)
    $safe = Get-SafeName $Name
    $state = New-Object psobject -Property @{
        Csr = $null; CsrPath = (Join-Path $Folder "$safe.csr"); CsrError = $null
        Signed = $null; SignedPath = $null; SignedError = $null; Leaf = $null; Extra = @()
    }
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder -PathType Container)) { return $state }
    if (Test-Path -LiteralPath $state.CsrPath -PathType Leaf) {
        try { $state.Csr = Get-CsrInfo ([System.IO.File]::ReadAllText($state.CsrPath)) }
        catch { $state.CsrError = $_.Exception.Message }
    }
    foreach ($ext in $script:SignedExtensions) {
        $p = Join-Path $Folder ($safe + $ext)
        if (Test-Path -LiteralPath $p -PathType Leaf) { $state.SignedPath = $p; break }
    }
    if ($state.SignedPath) {
        try {
            $state.Signed = ConvertTo-X509List ([System.IO.File]::ReadAllBytes($state.SignedPath))
            if ($state.Signed.Count -eq 0) { $state.SignedError = 'no certificate in it' }
        }
        catch { $state.SignedError = $_.Exception.Message }
        if ($state.Signed -and $state.Csr) {
            foreach ($c in $state.Signed) {
                if (Test-SameByte (Get-CertSpki $c) $state.Csr.Spki) { $state.Leaf = $c; break }
            }
            if ($state.Leaf) { $state.Extra = @($state.Signed | Where-Object { $_.Thumbprint -ne $state.Leaf.Thumbprint }) }
        }
    }
    $state
}

# ---------------------------------------------------------------------------------------
# vSphere
# ---------------------------------------------------------------------------------------

function Get-ServedCertificate {
    # What the host's port 443 serves right now. Cert is $null when it could not be read;
    # Retry says whether asking again could help (the port answered, or refused, as it
    # does while the agents restart) or not (no route, no name: a firewall, another DNS).
    param([string] $HostName, [int] $Port = $script:ServePort, [int] $TimeoutMs = 5000)
    $result = New-Object psobject -Property @{ Cert = $null; Retry = $false }
    # The system's default protocols first, then TLS 1.2 by name for an old .NET Framework.
    foreach ($protocol in @([System.Security.Authentication.SslProtocols]::None, [System.Security.Authentication.SslProtocols]::Tls12)) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $ar = $tcp.BeginConnect($HostName, $Port, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $result.Retry = $false; return $result }
            $tcp.EndConnect($ar)
            $result.Retry = $true
            $accept = [System.Net.Security.RemoteCertificateValidationCallback] { $true }
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $accept)
            $ssl.ReadTimeout = $TimeoutMs
            $ssl.WriteTimeout = $TimeoutMs
            $ssl.AuthenticateAsClient($HostName, $null, $protocol, $false)
            if ($ssl.RemoteCertificate) {
                $result.Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $ssl.RemoteCertificate
                return $result
            }
        }
        catch {
            $socket = $_.Exception
            while ($socket -and $socket -isnot [System.Net.Sockets.SocketException]) { $socket = $socket.InnerException }
            if ($socket -and "$($socket.SocketErrorCode)" -match '^Connection(Refused|Reset)$') { $result.Retry = $true }
            elseif ($socket -and -not $result.Retry) { return $result }      # no such name, no route
        }
        finally { $tcp.Close() }
    }
    $result
}

function Wait-VcTask {
    param($Vc, $TaskRef, [int] $Timeout)
    $deadline = (Get-Date).AddSeconds($Timeout)
    while ($true) {
        Start-Sleep -Seconds 2
        $t = Get-View -Server $Vc -Id $TaskRef -Property Info
        $state = "$($t.Info.State)"
        if ($state -eq 'success') { return }
        if ($state -eq 'error') {
            $msg = 'no reason given'
            if ($t.Info.Error) {
                $msg = $t.Info.Error.LocalizedMessage
                if (-not $msg -and $t.Info.Error.Fault) { $msg = $t.Info.Error.Fault.GetType().Name }
            }
            throw "the task failed: $msg"
        }
        if ((Get-Date) -gt $deadline) { throw "the task is still running after $Timeout s" }
    }
}

function Read-HostNow {
    param($Vc, $Ref)
    $v = Get-View -Server $Vc -Id $Ref -Property Name, Runtime.ConnectionState, Runtime.InMaintenanceMode, Config.Certificate
    $cert = $null
    if ($v.Config) { try { $cert = ConvertFrom-HostCertificate $v.Config.Certificate } catch { } }
    New-Object psobject -Property @{
        State       = "$($v.Runtime.ConnectionState)"
        Maintenance = [bool]$v.Runtime.InMaintenanceMode
        Cert        = $cert
    }
}

function Wait-NewCertificate {
    # Until the host is connected and vCenter shows a certificate other than $OldThumb
    # (or exactly $ExpectThumb). Returns the last reading; .Done says whether it got there.
    param($Vc, $Ref, [string] $OldThumb, [string] $ExpectThumb, [int] $Timeout)
    $deadline = (Get-Date).AddSeconds($Timeout)
    while ($true) {
        Start-Sleep -Seconds 3
        $now = Read-HostNow $Vc $Ref
        $done = $false
        if ($now.State -eq 'connected' -and $now.Cert) {
            if ($ExpectThumb) { $done = ($now.Cert.Thumbprint -eq $ExpectThumb) }
            else { $done = ($now.Cert.Thumbprint -ne $OldThumb) }
        }
        if ($done -or (Get-Date) -gt $deadline) {
            $now | Add-Member -NotePropertyName Done -NotePropertyValue $done
            return $now
        }
    }
}

function Test-Served {
    # 'yes', 'old' (still the previous certificate after the wait) or 'unreachable'.
    param([string] $Name, [string] $Thumb)
    $deadline = (Get-Date).AddSeconds($script:ServeTimeout)
    $misses = 0
    while ($true) {
        $served = Get-ServedCertificate $Name
        if ($served.Cert) {
            if ($served.Cert.Thumbprint -eq $Thumb) { return 'yes' }
            if ((Get-Date) -gt $deadline) { return 'old' }
            $misses = 0
        }
        else {
            $misses++
            if (-not $served.Retry -or $misses -ge 3 -or (Get-Date) -gt $deadline) { return 'unreachable' }
        }
        Start-Sleep -Seconds 5
    }
}

function Get-CaList {
    param($Vc, $HcmRef)
    $hcm = Get-View -Server $Vc -Id $HcmRef
    $out = @()
    foreach ($pem in @($hcm.ListCACertificates())) {
        if ($pem) { $out += ConvertTo-X509List ([System.Text.Encoding]::ASCII.GetBytes($pem)) }
    }
    $out
}

# ---------------------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------------------

function Invoke-SelfTest {
    $script:pass = 0; $script:fail = 0
    function Check([string] $What, [bool] $Ok) {
        if ($Ok) { $script:pass++; Write-Host "  ok    $What" }
        else { $script:fail++; Write-Host "  FAIL  $What" -ForegroundColor Red }
    }
    $X = 'System.Security.Cryptography.X509Certificates'
    $sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $pkcs1 = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    $now = Get-Date
    function NewReq([string] $Dn, $Key, $Hash) {
        if (-not $Hash) { $Hash = $sha256 }
        New-Object "$X.CertificateRequest" -ArgumentList $Dn, $Key, $Hash, $pkcs1
    }
    function AddCa($Req) {
        $Req.CertificateExtensions.Add((New-Object "$X.X509BasicConstraintsExtension" -ArgumentList $true, $false, 0, $true))
        $Req.CertificateExtensions.Add((New-Object "$X.X509KeyUsageExtension" -ArgumentList ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'KeyCertSign, CrlSign'), $true))
        $Req.CertificateExtensions.Add((New-Object "$X.X509SubjectKeyIdentifierExtension" -ArgumentList $Req.PublicKey, $false))
    }
    function AddLeaf($Req, [string[]] $Dns, $Usage, [string[]] $Eku) {
        $b = New-Object "$X.SubjectAlternativeNameBuilder"
        foreach ($d in $Dns) { $b.AddDnsName($d) }
        $Req.CertificateExtensions.Add($b.Build())
        if (-not $Usage) { $Usage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature, KeyEncipherment' }
        $Req.CertificateExtensions.Add((New-Object "$X.X509KeyUsageExtension" -ArgumentList $Usage, $true))
        if (-not $Eku) { $Eku = @('1.3.6.1.5.5.7.3.1') }
        $oids = New-Object System.Security.Cryptography.OidCollection
        foreach ($o in $Eku) { [void]$oids.Add((New-Object System.Security.Cryptography.Oid -ArgumentList $o)) }
        $Req.CertificateExtensions.Add((New-Object "$X.X509EnhancedKeyUsageExtension" -ArgumentList $oids, $false))
    }
    function Issue($Req, $Issuer, $From, $To) {
        $script:serialNo++
        $Req.Create($Issuer, [DateTimeOffset]$From, [DateTimeOffset]$To, [byte[]](0x10, [byte]($script:serialNo % 250)))
    }
    $script:serialNo = 0
    $pem = { param($c) "-----BEGIN CERTIFICATE-----`r`n" + [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks') + "`r`n-----END CERTIFICATE-----`r`n" }

    Write-Host "esxi-cert-renew $script:ToolVersion self-test"
    try { $null = [System.Security.Cryptography.X509Certificates.CertificateRequest] }
    catch { Write-Host '  the self-test needs .NET Framework 4.7.2 or later, or PowerShell 7' -ForegroundColor Yellow; return 1 }

    # A small PKI: root -> issuing CA -> host certificates.
    $rootKey = [System.Security.Cryptography.RSA]::Create(2048)
    $rootReq = NewReq 'CN=Test Root CA, O=Example, C=US' $rootKey; AddCa $rootReq
    $root = $rootReq.CreateSelfSigned([DateTimeOffset]$now.AddDays(-30), [DateTimeOffset]$now.AddYears(10))
    $intKey = [System.Security.Cryptography.RSA]::Create(2048)
    $intReq = NewReq 'CN=Test Issuing CA, O=Example, C=US' $intKey; AddCa $intReq
    $int = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey((Issue $intReq $root $now.AddDays(-30) $now.AddYears(5)), $intKey)
    $name = 'esx01.example.com'
    $hostKey = [System.Security.Cryptography.RSA]::Create(2048)
    $hostReq = NewReq "CN=$name, O=Example" $hostKey; AddLeaf $hostReq @($name)
    $csrPem = "-----BEGIN CERTIFICATE REQUEST-----`n" + [Convert]::ToBase64String($hostReq.CreateSigningRequest(), 'InsertLineBreaks') + "`n-----END CERTIFICATE REQUEST-----`n"
    $good = Issue $hostReq $int $now.AddDays(-1) $now.AddDays(365)
    $rootPub = ConvertTo-X509 $root.RawData
    $intPub = ConvertTo-X509 $int.RawData

    Write-Host 'parsing'
    $bundle = [System.Text.Encoding]::ASCII.GetBytes("subject=whatever`r`n" + (& $pem $good) + (& $pem $intPub) + (& $pem $rootPub))
    $list = ConvertTo-X509List $bundle
    Check 'a PEM bundle with CRLF line ends gives three certificates in order' ($list.Count -eq 3 -and $list[0].Thumbprint -eq $good.Thumbprint -and $list[2].Thumbprint -eq $rootPub.Thumbprint)
    Check 'a DER certificate reads too' ((ConvertTo-X509List $good.RawData)[0].Thumbprint -eq $good.Thumbprint)
    $sb = [System.Text.Encoding]::ASCII.GetBytes((& $pem $good))
    $signed = New-Object 'System.SByte[]' $sb.Length
    [System.Buffer]::BlockCopy($sb, 0, $signed, 0, $sb.Length)
    Check 'config.certificate as signed bytes reads' ((ConvertFrom-HostCertificate $signed).Thumbprint -eq $good.Thumbprint)
    Check 'an empty config.certificate gives nothing' ($null -eq (ConvertFrom-HostCertificate $null))
    $both = New-Object "$X.X509Certificate2Collection"
    [void]$both.Add($good); [void]$both.Add($intPub)
    $p7 = $both.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7)
    $p7list = ConvertTo-X509List $p7
    Check 'a PKCS#7 bundle (.p7b) reads' ($p7list.Count -eq 2 -and @($p7list | Where-Object { $_.Thumbprint -eq $good.Thumbprint }).Count -eq 1)
    $p7pem = [System.Text.Encoding]::ASCII.GetBytes("-----BEGIN CERTIFICATE-----`r`n" + [Convert]::ToBase64String($p7, 'InsertLineBreaks') + "`r`n-----END CERTIFICATE-----`r`n")
    $p7list = ConvertTo-X509List $p7pem
    Check 'PKCS#7 inside CERTIFICATE lines reads (a Microsoft CA chain download)' ($p7list.Count -eq 2 -and @($p7list | Where-Object { $_.Thumbprint -eq $good.Thumbprint }).Count -eq 1)
    $csr = Get-CsrInfo $csrPem
    Check 'CSR: common name' ($csr.CommonName -eq $name)
    Check 'CSR: DNS Subject Alternative Name' (@($csr.Dns) -contains $name)
    Check 'CSR: public key matches the certificate issued for it' (Test-SameByte $csr.Spki (Get-CertSpki $good))
    Check 'certificate SAN reads' (@((Get-SanName $good).Dns) -contains $name)
    $ipReq = NewReq 'CN=192.0.2.10' $hostKey
    $sanIp = New-Object "$X.SubjectAlternativeNameBuilder"
    $sanIp.AddIpAddress([System.Net.IPAddress]::Parse('192.0.2.10')); $sanIp.AddIpAddress([System.Net.IPAddress]::Parse('2001:db8::10'))
    $ipReq.CertificateExtensions.Add($sanIp.Build())
    $ipSan = Get-SanName (Issue $ipReq $int $now.AddDays(-1) $now.AddDays(365))
    Check 'a host known by its address: IPv4 SAN matches' ((Test-NameIn '192.0.2.10' $ipSan.Dns $ipSan.Ip) -and -not (Test-NameIn '192.0.2.11' $ipSan.Dns $ipSan.Ip))
    Check 'an IPv6 SAN matches however the address is written' (Test-NameIn '2001:DB8:0:0:0:0:0:10' $ipSan.Dns $ipSan.Ip)
    Check 'names are not mistaken for addresses' ((Test-IsIp '192.0.2.10') -and (Test-IsIp '2001:db8::1') -and -not (Test-IsIp 'esx01.example.com') -and -not (Test-IsIp '10'))
    Check 'VMCA issuer recognised' (Test-VmcaIssuer 'CN=CA, DC=vsphere, DC=local, C=US, ST=California, O=vcsa.example.com, OU=VMware Engineering')
    Check 'VMCA issuer recognised in reverse order' (Test-VmcaIssuer 'OU=VMware Engineering, O=vcsa.example.com, ST=California, C=US, DC=local, DC=vsphere, CN=CA')
    Check 'an enterprise CA is not VMCA' (-not (Test-VmcaIssuer 'CN=Example Issuing CA 1, O=Example, C=US'))
    $savedName = $script:VmcaName
    $script:VmcaName = 'Example VMCA'
    Check '-VmcaIssuer names a VMCA that is not called CA' ((Test-VmcaIssuer 'CN=Example VMCA, O=Example, C=US') -and -not (Test-VmcaIssuer 'CN=Example Issuing CA 1, O=Example, C=US'))
    $script:VmcaName = $savedName
    Check '-Subject becomes the DN PowerCLI sends' ((ConvertTo-CsrDn 'O=Example, OU=Infrastructure, L=Reston, ST=Virginia, C=us' $name) -ceq "CN = $name, C = US, L = Reston, ST = Virginia, O = Example, OU = Infrastructure")
    $threw = 0
    foreach ($bad in 'O=Example, C=US', 'CN=x, C=US, ST=Virginia, L=Reston, O=Example, OU=Infrastructure', 'C=USA, ST=Virginia, L=Reston, O=Example, OU=Infrastructure', 'C=US, ST=Virginia, L=Reston, O=Example, OU=') {
        try { [void](ConvertTo-CsrDn $bad $name) } catch { $threw++ }
    }
    Check '-Subject: a missing field, a CN, a long country code and an empty value are refused' ($threw -eq 4)
    $vmcaKey = [System.Security.Cryptography.RSA]::Create(2048)
    $vmcaOld = (NewReq 'CN=CA, DC=vsphere, DC=local, C=US, ST=California, O=vcsa.example.com, OU=VMware Engineering' $vmcaKey).CreateSelfSigned([DateTimeOffset]$now.AddYears(-9), [DateTimeOffset]$now.AddDays(100))
    $vmcaNew = (NewReq 'CN=CA, DC=vsphere, DC=local, C=US, ST=California, O=vcsa.example.com, OU=VMware Engineering' $vmcaKey).CreateSelfSigned([DateTimeOffset]$now.AddDays(-1), [DateTimeOffset]$now.AddYears(10))
    Check 'VMCA end: the latest VMCA CA certificate on the list counts' ((Get-VmcaEnd @($rootPub, $vmcaOld, $vmcaNew)) -eq $vmcaNew.NotAfter)
    Check 'VMCA end: none on the list gives nothing' ($null -eq (Get-VmcaEnd @($rootPub, $intPub)))
    Check 'VMCA limit: a root ending with the host certificate cannot help' (Test-VmcaLimit $now.AddDays(20) $now.AddDays(20) $now 30)
    Check 'VMCA limit: a root ending inside the -Days window cannot help' (Test-VmcaLimit $now.AddDays(25) $now.AddDays(10) $now 30)
    Check 'VMCA limit: a root with years left is no limit' (-not (Test-VmcaLimit $now.AddDays(1200) $now.AddDays(10) $now 30))
    Check 'version text compares numerically' ((ConvertTo-ApiVersion '8.0.3.0') -ge $script:CustomMinimum -and (ConvertTo-ApiVersion '8.0.2.0') -lt $script:CustomMinimum -and (ConvertTo-ApiVersion '9.0.0.0') -ge $script:CustomMinimum)

    Write-Host 'signed certificate checks'
    Check 'a good certificate has no problems' (@(Get-LeafProblem $good $name $csr $now 30).Count -eq 0)
    $otherKey = [System.Security.Cryptography.RSA]::Create(2048)
    $r = NewReq "CN=$name" $otherKey; AddLeaf $r @($name)
    Check 'a certificate for another key is refused' ((@(Get-LeafProblem (Issue $r $int $now.AddDays(-1) $now.AddDays(365)) $name $csr $now 30) -match 'public key').Count -eq 1)
    $r = NewReq "CN=$name" $hostKey; AddLeaf $r @('esx02.example.com')
    Check 'a SAN without the host is refused' ((@(Get-LeafProblem (Issue $r $int $now.AddDays(-1) $now.AddDays(365)) $name $csr $now 30) -match 'Alternative Name').Count -eq 1)
    $r = NewReq "CN=$name" $hostKey; AddLeaf $r @($name, '*.example.com')
    Check 'a wildcard is refused' ((@(Get-LeafProblem (Issue $r $int $now.AddDays(-1) $now.AddDays(365)) $name $csr $now 30) -match 'wildcard').Count -eq 1)
    $r = NewReq 'CN=esx01' $hostKey; AddLeaf $r @($name)
    Check 'a short common name is refused' ((@(Get-LeafProblem (Issue $r $int $now.AddDays(-1) $now.AddDays(365)) $name $csr $now 30) -match 'common name').Count -eq 1)
    Check 'a certificate expiring within -Days is refused' ((@(Get-LeafProblem (Issue $hostReq $int $now.AddDays(-1) $now.AddDays(20)) $name $csr $now 30) -match 'expires').Count -eq 1)
    Check 'a certificate not valid yet is refused' ((@(Get-LeafProblem (Issue $hostReq $int $now.AddDays(2) $now.AddDays(365)) $name $csr $now 30) -match 'not valid before').Count -eq 1)
    $r = NewReq "CN=$name" $hostKey ([System.Security.Cryptography.HashAlgorithmName]::SHA1); AddLeaf $r @($name)
    $sha1 = $null
    try { $sha1 = Issue $r $int $now.AddDays(-1) $now.AddDays(365) } catch { }
    if ($sha1 -and $sha1.SignatureAlgorithm.Value -eq '1.2.840.113549.1.1.5') { Check 'a SHA-1 signature is refused' ((@(Get-LeafProblem $sha1 $name $csr $now 30) -match 'SHA-1').Count -eq 1) }
    else {
        $sha1 = Issue $hostReq $int $now.AddDays(-1) $now.AddDays(365)
        Check 'SHA-1 cannot be produced on this platform; the check reads the signature OID instead' ($script:WeakSignature['1.2.840.113549.1.1.5'] -eq 'SHA-1' -and -not $script:WeakSignature.ContainsKey($sha1.SignatureAlgorithm.Value))
    }
    $r = NewReq "CN=$name" $hostKey; AddLeaf $r @($name) ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature')
    Check 'a key usage without Key Encipherment is refused' ((@(Get-LeafProblem (Issue $r $int $now.AddDays(-1) $now.AddDays(365)) $name $csr $now 30) -match 'key usage').Count -eq 1)
    $r = NewReq "CN=$name" $hostKey; AddLeaf $r @($name) $null @('1.3.6.1.5.5.7.3.2')
    Check 'an extended key usage without server authentication is refused' ((@(Get-LeafProblem (Issue $r $int $now.AddDays(-1) $now.AddDays(365)) $name $csr $now 30) -match 'server authentication').Count -eq 1)
    $r = NewReq "CN=$name" $hostKey; AddCa $r
    Check 'a CA certificate is refused' ((@(Get-LeafProblem (Issue $r $int $now.AddDays(-1) $now.AddDays(365)) $name $csr $now 30) -match 'CA certificate').Count -eq 1)

    Write-Host 'chain checks'
    $c = Get-ChainCheck $good @() @($intPub, $rootPub) $now
    Check 'root and issuing CA on the list: trusted' (@($c.Problems).Count -eq 0 -and @($c.Cas).Count -eq 2)
    $c = Get-ChainCheck $good @($intPub) @($rootPub) $now
    Check 'issuing CA only in the file: refused, vCenter must trust it too' ((@($c.Problems) -match 'Test Issuing CA').Count -ge 1)
    $c = Get-ChainCheck $good @() @() $now
    Check 'nothing to chain to: refused' (@($c.Problems).Count -ge 1)
    $c = Get-ChainCheck $good @($intPub, $rootPub) @() $now
    Check 'whole chain only in the file: refused' ((@($c.Problems) -match 'does not trust').Count -ge 1)
    $selfSigned = $hostReq.CreateSelfSigned([DateTimeOffset]$now.AddDays(-1), [DateTimeOffset]$now.AddDays(365))
    $c = Get-ChainCheck (ConvertTo-X509 $selfSigned.RawData) @() @($intPub, $rootPub) $now
    Check 'a self-signed certificate: refused' ((@($c.Problems) -match 'self-signed').Count -eq 1)

    Write-Host 'decisions'
    $base = @{ Name = $name; Connected = $true; State = 'connected'; Maintenance = $false; Cert = $good; NotAfter = $now.AddDays(10); IsVmca = $true; Issuer = 'CA'; Api = [version]'8.0.3'; ManagedBy = ''; OwnName = $name }
    $ctx = @{ Mode = 'vmca'; Days = 30; All = $false; Now = $now; VcApi = [version]'8.0.3'; Folder = $false }
    $noFiles = New-Object psobject -Property @{ Csr = $null; CsrPath = 'x.csr'; CsrError = $null; Signed = $null; SignedPath = $null; SignedError = $null; Leaf = $null }
    function D($HOver, $COver, $F) {
        $h = $base.Clone(); foreach ($k in $HOver.Keys) { $h[$k] = $HOver[$k] }
        $cx = $ctx.Clone(); foreach ($k in $COver.Keys) { $cx[$k] = $COver[$k] }
        if (-not $F) { $F = $noFiles }
        Get-Decision (New-Object psobject -Property $h) (New-Object psobject -Property $cx) $F
    }
    Check 'vmca: expiring, connected, VMCA issued -> renew' ((D @{} @{}).Action -eq 'renew')
    Check 'vmca: 400 days left -> nothing' ((D @{ NotAfter = $now.AddDays(400) } @{}).Action -eq 'none')
    Check 'vmca: 400 days left with -All -> renew' ((D @{ NotAfter = $now.AddDays(400) } @{ All = $true }).Action -eq 'renew')
    Check 'vmca: in maintenance mode -> skip' ((D @{ Maintenance = $true } @{}).Action -eq 'skip')
    Check 'vmca: not connected -> skip' ((D @{ Connected = $false; State = 'notResponding' } @{}).Action -eq 'skip')
    $d = D @{ IsVmca = $false; Issuer = 'Example Issuing CA 1' } @{}
    Check 'vmca: certificate from another CA -> skip, never replaced, issuer named' ($d.Action -eq 'skip' -and $d.Reason -match "'Example Issuing CA 1'")
    Check 'vmca: certificate already expired -> renew' ((D @{ NotAfter = $now.AddDays(-3) } @{}).Action -eq 'renew')
    Check 'thumbprint mode -> nothing' ((D @{} @{ Mode = 'thumbprint' }).Action -eq 'none')
    Check 'custom without -CertFolder -> nothing, says why' ((D @{ IsVmca = $false } @{ Mode = 'custom' }).Reason -match 'CertFolder')
    Check 'custom: expiring, no files -> write a CSR' ((D @{ IsVmca = $false } @{ Mode = 'custom'; Folder = $true }).Action -eq 'csr')
    Check 'custom: still on VMCA, 900 days left -> write a CSR' ((D @{ NotAfter = $now.AddDays(900) } @{ Mode = 'custom'; Folder = $true }).Action -eq 'csr')
    Check 'custom: 900 days left, CA certificate -> nothing' ((D @{ IsVmca = $false; NotAfter = $now.AddDays(900) } @{ Mode = 'custom'; Folder = $true }).Action -eq 'none')
    Check 'custom: ESXi 8.0.2 -> skip' ((D @{ IsVmca = $false; Api = [version]'8.0.2' } @{ Mode = 'custom'; Folder = $true }).Action -eq 'skip')
    Check 'custom: vCenter 8.0.2 -> skip' ((D @{ IsVmca = $false } @{ Mode = 'custom'; Folder = $true; VcApi = [version]'8.0.2' }).Action -eq 'skip')
    $f = New-Object psobject -Property @{ Csr = $csr; CsrPath = 'esx01.example.com.csr'; CsrError = $null; Signed = $null; SignedPath = $null; SignedError = $null; Leaf = $null }
    Check 'custom: CSR written, nothing signed yet -> wait' ((D @{ IsVmca = $false } @{ Mode = 'custom'; Folder = $true } $f).Action -eq 'wait')
    $f = New-Object psobject -Property @{ Csr = $csr; CsrPath = 'esx01.example.com.csr'; CsrError = $null; Signed = @($good); SignedPath = 'esx01.example.com.crt'; SignedError = $null; Leaf = $good }
    Check 'custom: signed certificate for the CSR -> install' ((D @{ IsVmca = $false; Cert = $intPub } @{ Mode = 'custom'; Folder = $true } $f).Action -eq 'install')
    Check 'custom: that certificate already on the host -> nothing' ((D @{ IsVmca = $false; NotAfter = $now.AddDays(365) } @{ Mode = 'custom'; Folder = $true } $f).Action -eq 'none')
    Check 'custom: already installed and due again -> skip, wants a new folder' ((D @{ IsVmca = $false } @{ Mode = 'custom'; Folder = $true } $f).Reason -match 'new -CertFolder')
    $f = New-Object psobject -Property @{ Csr = $null; CsrPath = 'esx01.example.com.csr'; CsrError = $null; Signed = @($good); SignedPath = 'esx01.example.com.crt'; SignedError = $null; Leaf = $null }
    Check 'custom: certificate without our CSR -> skip' ((D @{ IsVmca = $false } @{ Mode = 'custom'; Folder = $true } $f).Action -eq 'skip')
    $f = New-Object psobject -Property @{ Csr = $null; CsrPath = 'esx01.example.com.csr'; CsrError = 'not a PEM certificate request'; Signed = $null; SignedPath = $null; SignedError = $null; Leaf = $null }
    Check 'custom: a CSR file that cannot be read -> skip, never overwritten' ((D @{ IsVmca = $false } @{ Mode = 'custom'; Folder = $true } $f).Reason -match 'cannot read esx01.example.com.csr')
    Check 'standalone ESXi managed by a vCenter -> nothing, points at the vCenter' ((D @{ ManagedBy = '192.0.2.5' } @{ Mode = 'standalone'; Folder = $true }).Reason -match 'vCenter 192.0.2.5')
    Check 'custom: the host calls itself something else -> skip (KB 397317)' ((D @{ IsVmca = $false; OwnName = 'esx01-old.example.com' } @{ Mode = 'custom'; Folder = $true }).Reason -match '397317')
    Check 'vmca: a host name mismatch does not stop a VMCA renewal' ((D @{ OwnName = 'esx01-old.example.com' } @{}).Action -eq 'renew')
    Check 'host name: short name plus domain' ((Get-OwnName 'esx01' 'example.com') -eq 'esx01.example.com' -and (Get-OwnName 'esx01.example.com' 'example.com') -eq 'esx01.example.com')
    Check 'standalone ESXi: expiring -> write a CSR' ((D @{ IsVmca = $false } @{ Mode = 'standalone'; Folder = $true }).Action -eq 'csr')

    Write-Host ''
    if ($script:fail -gt 0) { Write-Host "$script:fail of $($script:pass + $script:fail) checks FAILED" -ForegroundColor Red; return 1 }
    Write-Host "all $script:pass checks passed"
    0
}

# ---------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------

if ($SelfTest) { $rc = @(Invoke-SelfTest)[-1]; exit $rc }

if (-not $Server) { throw 'Give -Server (a vCenter, or an ESXi host no vCenter manages), or -SelfTest.' }
if ($Subject -and -not $CertFolder) { throw '-Subject goes with -CertFolder (custom mode).' }
if ($Subject) { [void](ConvertTo-CsrDn $Subject 'host.example.com') }      # fail now, not at the first host
if ($CertFolder) { $CertFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CertFolder) }

if (-not (Get-Command Connect-VIServer -ErrorAction SilentlyContinue)) {
    try { Import-Module VMware.VimAutomation.Core -ErrorAction Stop -WarningAction SilentlyContinue }
    catch { throw 'PowerCLI is not installed. Install-Module VCF.PowerCLI (or VMware.PowerCLI 13), then run this again.' }
}

$now = Get-Date
$results = New-Object System.Collections.ArrayList
$failed = $false
$ours = $false
$vc = $null
$defaults = Get-Variable -Name DefaultVIServers -Scope Global -ValueOnly -ErrorAction SilentlyContinue
foreach ($s in @($defaults)) { if ($s -and $s.IsConnected -and $s.Name -eq $Server) { $vc = $s; break } }

try {
    if (-not $vc) {
        $connect = @{ Server = $Server; ErrorAction = 'Stop' }
        if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) { $connect.Credential = $Credential }
        $vc = Connect-VIServer @connect
        $ours = $true
    }
    $vcApi = ConvertTo-ApiVersion $vc.ExtensionData.Content.About.ApiVersion
    # ESXi 8.0 U3 certificate replacement needs NotifyAffectedServices, which older PowerCLI lacks.
    $hcmType = 'VMware.Vim.HostCertificateManager' -as [type]
    $canNotify = ($null -ne $hcmType) -and (@($hcmType.GetMethods() | Where-Object { $_.Name -eq 'NotifyAffectedServices' }).Count -gt 0)
    $isVc = ($vc.ProductLine -eq 'vpx')

    # Certificate mode
    $mode = 'standalone'
    if ($isVc) {
        $setting = Get-AdvancedSetting -Entity $vc -Server $vc -Name 'vpxd.certmgmt.mode' -ErrorAction SilentlyContinue
        $mode = 'vmca'
        if ($setting) { $mode = "$(@($setting)[0].Value)".Trim() }
        if (@('vmca', 'custom', 'thumbprint') -cnotcontains $mode) {
            throw "vpxd.certmgmt.mode is '$mode'. vCenter reads vmca, custom or thumbprint, lower case only: fix the value first."
        }
        $dv = Get-AdvancedSetting -Entity $vc -Server $vc -Name 'vpxd.certmgmt.certs.daysValid' -ErrorAction SilentlyContinue
        $n = 0
        if ($dv -and [int]::TryParse("$(@($dv)[0].Value)", [ref]$n) -and $n -gt 0) { $script:DaysValid = $n }
        if ($mode -eq 'vmca' -and $CertFolder) {
            throw "vCenter is in vmca mode; -CertFolder is for custom mode. To keep certificates from your own CA, set vpxd.certmgmt.mode to custom and add the CA chain to vCenter's trusted roots first (README)."
        }
    }

    # Hosts
    $props = 'Name', 'Parent', 'Runtime.ConnectionState', 'Runtime.InMaintenanceMode', 'Config.Certificate', 'Config.Product', 'Config.Network.DnsConfig', 'ConfigManager.CertificateManager', 'Summary.ManagementServerIp'
    $views = @(Get-View -Server $vc -ViewType HostSystem -Property $props | Sort-Object Name)
    $clusterName = @{}
    if ($isVc) { foreach ($c in @(Get-View -Server $vc -ViewType ClusterComputeResource -Property Name)) { $clusterName[$c.MoRef.Value] = $c.Name } }

    # Every host, in scope or not: cluster peers are checked whatever -VMHost and -Cluster say.
    $everyHost = @()
    foreach ($v in $views) {
        $cert = $null
        try { $cert = ConvertFrom-HostCertificate $v.Config.Certificate } catch { }
        $product = $null
        if ($v.Config) { $product = $v.Config.Product }
        $hcmRef = $null
        if ($v.ConfigManager) { $hcmRef = $v.ConfigManager.CertificateManager }
        $h = New-Object psobject -Property @{
            Name        = $v.Name
            Ref         = $v.MoRef
            HcmRef      = $hcmRef
            Cluster     = "$($clusterName[$v.Parent.Value])"
            ClusterRef  = $v.Parent.Value
            State       = "$($v.Runtime.ConnectionState)"
            Connected   = ("$($v.Runtime.ConnectionState)" -eq 'connected')
            Maintenance = [bool]$v.Runtime.InMaintenanceMode
            Version     = ''
            Api         = [version]'0.0'
            Cert        = $cert
            NotAfter    = [datetime]::MinValue
            IsVmca      = $false
            Issuer      = ''
            ManagedBy   = ''
            OwnName     = ''
        }
        if ($product) { $h.Version = "$($product.Version)"; $h.Api = ConvertTo-ApiVersion $product.ApiVersion }
        if ($v.Config -and $v.Config.Network -and $v.Config.Network.DnsConfig) { $h.OwnName = Get-OwnName $v.Config.Network.DnsConfig.HostName $v.Config.Network.DnsConfig.DomainName }
        if ($cert) { $h.NotAfter = $cert.NotAfter; $h.IsVmca = Test-VmcaIssuer $cert.Issuer; $h.Issuer = Get-CommonName $cert.Issuer }
        if (-not $isVc -and $v.Summary) { $h.ManagedBy = "$($v.Summary.ManagementServerIp)" }
        $everyHost += $h
    }

    foreach ($p in @($VMHost) + @($Cluster)) { if ($null -ne $p -and $p -match '^\s*$') { throw 'An empty -VMHost or -Cluster name.' } }
    $hosts = $everyHost
    if ($VMHost) {
        foreach ($p in $VMHost) { if (-not @($hosts | Where-Object { $_.Name -like $p }).Count) { throw "No host matches '$p'." } }
        $hosts = @($hosts | Where-Object { $n = $_.Name; @($VMHost | Where-Object { $n -like $_ }).Count -gt 0 })
    }
    if ($Cluster) {
        foreach ($p in $Cluster) { if (-not @($clusterName.Values | Where-Object { $_ -like $p }).Count) { throw "No cluster matches '$p'." } }
        $hosts = @($hosts | Where-Object { $cn = $_.Cluster; $cn -and @($Cluster | Where-Object { $cn -like $_ }).Count -gt 0 })
    }
    $hosts = @($hosts | Sort-Object @{ Expression = { [int](-not $_.Cluster) } }, Cluster, Name)      # hosts outside a cluster last

    # Header
    $target = "vCenter $($vc.Name) ($($vc.Version)), certificate mode $mode"
    if (-not $isVc) { $target = "ESXi $($vc.Name) ($($vc.Version)), connected directly" }
    Write-Host "esxi-cert-renew $script:ToolVersion  $target"
    $scope = "renew certificates that expire within $Days days"
    if ($All) { $scope = 'renew every host in scope' }
    $modeLine = 'plan only: nothing is changed (add -Commit)'
    if ($Commit) { $modeLine = 'COMMIT: changes are made, one host at a time' }
    Write-Host "$scope; $modeLine"
    if ($CertFolder) { Write-Host "certificate folder: $CertFolder" }
    Write-Host ''
    if (-not $hosts.Count) { Write-Host 'No hosts in scope.' ; return }

    # Plan
    $ctx = New-Object psobject -Property @{ Mode = $mode; Days = $Days; All = [bool]$All; Now = $now; VcApi = $vcApi; Folder = [bool]$CertFolder }
    foreach ($h in $hosts) {
        $f = New-Object psobject -Property @{ Csr = $null; CsrPath = ''; CsrError = $null; Signed = $null; SignedPath = $null; SignedError = $null; Leaf = $null; Extra = @() }
        if ($CertFolder) { $f = Get-FolderState $CertFolder $h.Name }
        $d = Get-Decision $h $ctx $f
        if ($d.Action -in @('csr', 'install') -and -not $canNotify) { $d.Action = 'skip'; $d.Reason = 'this PowerCLI predates ESXi 8.0 Update 3 certificate replacement: update to VCF.PowerCLI 9 or VMware.PowerCLI 13.3 or later' }
        if ($d.Action -eq 'install') {
            $problems = @(Get-LeafProblem $f.Leaf $h.Name $f.Csr $now $Days)
            if ($problems.Count) { $d.Action = 'skip'; $d.Reason = "$(Split-Path -Leaf $f.SignedPath): " + ($problems -join '; ') }
        }
        $h | Add-Member -NotePropertyName Folder -NotePropertyValue $f
        $h | Add-Member -NotePropertyName Action -NotePropertyValue $d.Action
        $h | Add-Member -NotePropertyName Reason -NotePropertyValue $d.Reason
        $h | Add-Member -NotePropertyName Result -NotePropertyValue ''
        $h | Add-Member -NotePropertyName NewCert -NotePropertyValue $null
    }

    # VMCA renewals cannot outlast VMCA's own CA certificate: say so in the plan. -Commit
    # refreshes the host's CA list first (Renew does that anyway) and checks again.
    foreach ($h in @($hosts | Where-Object { $_.Action -eq 'renew' })) {
        $end = $null
        try { $end = Get-VmcaEnd (Get-CaList $vc $h.HcmRef) } catch { }
        if ($null -eq $end) { continue }
        if (Test-VmcaLimit $end $h.NotAfter $now $Days) { $h.Reason += "; but VMCA's CA certificate on its list expires $(Format-Day $end) and a renewal cannot outlast it: -Commit refreshes the list from vCenter and renews only if that helps (KB 419417)" }
        elseif ($end -lt $now.AddDays($script:DaysValid)) { $h.Reason += "; the new certificate ends $(Format-Day $end) with VMCA's CA certificate" }
    }

    # Custom installs: the CA list after "Refresh CA Certificates" is vCenter's TRUSTED_ROOTS.
    # Every connected host in the cluster must list the new certificate's CAs (HA and vSAN
    # peers check each other), so read the lists now and refresh the ones that lack them.
    $caCache = @{}
    $readCa = {
        param($hh)
        if (-not $caCache.ContainsKey($hh.Name)) {
            try { $caCache[$hh.Name] = New-Object psobject -Property @{ List = @(Get-CaList $vc $hh.HcmRef); Error = '' } }
            catch { $caCache[$hh.Name] = New-Object psobject -Property @{ List = @(); Error = $_.Exception.Message } }
        }
        $caCache[$hh.Name]
    }
    $lacksCa = {
        # Does host $hh lack any of the CA certificates in $cas on its list?
        param($hh, $cas)
        $l = & $readCa $hh
        foreach ($ca in @($cas)) { if (-not @($l.List | Where-Object { $_.Thumbprint -eq $ca.Thumbprint }).Count) { return $true } }
        $false
    }
    $told = @{}
    foreach ($h in @($hosts | Where-Object { $_.Action -eq 'install' })) {
        if ($mode -eq 'standalone') {
            $h | Add-Member -NotePropertyName Peers -NotePropertyValue @()
            continue
        }
        $peers = @($h)
        if ($h.Cluster) { $peers = @($everyHost | Where-Object { $_.ClusterRef -eq $h.ClusterRef -and $_.Connected }) }
        $check = Get-ChainCheck $h.Folder.Leaf $h.Folder.Extra (& $readCa $h).List $now
        # A chain this host does not list yet may still be in vCenter: refresh every peer, then decide.
        $lacking = $peers
        if (-not @($check.Problems).Count) { $lacking = @($peers | Where-Object { & $lacksCa $_ $check.Cas }) }
        $h | Add-Member -NotePropertyName Peers -NotePropertyValue $lacking
        # Said once per cluster: the refresh happens before the first installation there.
        $group = $h.Name
        if ($h.Cluster) { $group = $h.ClusterRef }
        if ($lacking.Count -and -not $told.ContainsKey($group)) {
            $told[$group] = $true
            $who = 'its CA certificates'
            if ($h.Cluster) { $who = "CA certificates on the $($lacking.Count) host(s) of $($h.Cluster) that do not list its CA chain" }
            $h.Reason += "; first refresh $who, and install only if vCenter trusts the chain"
        }
    }

    # Print the plan
    $verb = @{ renew = 'RENEW through VMCA'; csr = 'WRITE CSR'; install = 'INSTALL'; wait = 'waiting'; skip = 'SKIP'; none = 'ok' }
    if (-not $Commit) { $verb = @{ renew = 'WOULD renew through VMCA'; csr = 'WOULD write CSR'; install = 'WOULD install'; wait = 'waiting'; skip = 'SKIP'; none = 'ok' } }
    $w = [Math]::Max(4, ($hosts | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum)
    $cw = [Math]::Max(7, ($hosts | ForEach-Object { $_.Cluster.Length } | Measure-Object -Maximum).Maximum)
    Write-Host ("{0}  {1}  {2,-10}  {3,5}  {4,-20}  {5}" -f 'HOST'.PadRight($w), 'CLUSTER'.PadRight($cw), 'EXPIRES', 'DAYS', 'ISSUER', 'PLAN')
    foreach ($h in $hosts) {
        $exp = '-'; $left = '-'
        if ($h.Cert) { $exp = Format-Day $h.NotAfter; $left = [int][Math]::Floor(($h.NotAfter - $now).TotalDays) }
        $issuer = $h.Issuer
        if ($h.IsVmca) { $issuer = 'VMCA' }
        if ($issuer.Length -gt 20) { $issuer = $issuer.Substring(0, 19) + '~' }
        $line = "{0}  {1}  {2,-10}  {3,5}  {4,-20}  {5}: {6}" -f $h.Name.PadRight($w), $h.Cluster.PadRight($cw), $exp, $left, $issuer, $verb[$h.Action], $h.Reason
        if ($h.Action -eq 'none') { $line = "{0}  {1}  {2,-10}  {3,5}  {4,-20}  {5}" -f $h.Name.PadRight($w), $h.Cluster.PadRight($cw), $exp, $left, $issuer, $h.Reason }
        if ($h.Action -eq 'skip') { Write-Host $line -ForegroundColor Yellow }
        else { Write-Host $line }
        $h.Result = 'ok'
        if ($h.Action -in @('renew', 'csr', 'install')) { $h.Result = 'planned' }
        if ($h.Action -eq 'skip') { $h.Result = 'skipped' }
        if ($h.Action -eq 'wait') { $h.Result = 'waiting' }
    }
    Write-Host ''
    $work = @($hosts | Where-Object { $_.Action -in @('renew', 'csr', 'install') })
    if (-not $work.Count) { Write-Host 'Nothing to do.' }
    elseif (-not $Commit) { Write-Host "$($work.Count) host(s) to change. Run again with -Commit." }

    # Commit
    if ($Commit -and $work.Count) {
        if ($CertFolder -and -not (Test-Path -LiteralPath $CertFolder)) { [void](New-Item -ItemType Directory -Path $CertFolder) }
        $certMgr = $null
        if ($isVc) { $certMgr = Get-View -Server $vc -Id $vc.ExtensionData.Content.CertificateManager }
        $refreshed = @{}
        foreach ($h in $work) {
            if ($failed) { $h.Result = 'not attempted'; continue }
            $tag = "  $($h.Name):"
            try {
                $before = Read-HostNow $vc $h.Ref
                if ($before.State -ne 'connected') { throw "it is $($before.State) now; nothing was changed" }
                if (-not $before.Cert -or $before.Cert.Thumbprint -ne $h.Cert.Thumbprint) { throw 'its certificate changed since the plan was made; nothing was changed, run again' }

                if ($h.Action -eq 'renew') {
                    if ($before.Maintenance) { throw 'it entered maintenance mode; nothing was changed' }
                    Write-Host "$tag refreshing CA certificates"
                    Wait-VcTask $vc ($certMgr.CertMgrRefreshCACertificatesAndCRLs_Task(@($h.Ref))) $script:TaskTimeout
                    $end = $null
                    try { $end = Get-VmcaEnd (Get-CaList $vc $h.HcmRef) } catch { }      # the check after the renewal still holds
                    if ($null -ne $end -and (Test-VmcaLimit $end $before.Cert.NotAfter $now $Days)) {
                        throw "nothing was changed: VMCA's CA certificate expires $(Format-Day $end) and a renewal cannot outlast it. Renew the VMCA root first (KB 419417)"
                    }
                    Write-Host "$tag renewing through VMCA"
                    Wait-VcTask $vc ($certMgr.CertMgrRefreshCertificates_Task(@($h.Ref))) $script:TaskTimeout
                    $after = Wait-NewCertificate $vc $h.Ref $before.Cert.Thumbprint $null $script:SettleTimeout
                    if (-not $after.Done) {
                        if ($after.State -ne 'connected') { throw "the renewal ran but the host is $($after.State) after $script:SettleTimeout s; check it in the vSphere Client" }
                        throw "the renewal ran but vCenter still shows the old certificate after $script:SettleTimeout s"
                    }
                    if ($after.Cert.NotAfter -le $before.Cert.NotAfter.AddDays(1)) {
                        throw "the host has a new certificate, but it still expires $(Format-Day $after.Cert.NotAfter): VMCA's root expires then, so renew the VMCA root first (KB 419417)"
                    }
                }
                elseif ($h.Action -eq 'csr') {
                    $hcm = Get-View -Server $vc -Id $h.HcmRef
                    Write-Host "$tag generating a CSR on the host"
                    if ($Subject) { $csrPem = $hcm.GenerateCertificateSigningRequestByDn((ConvertTo-CsrDn $Subject $h.Name)) }
                    else { $csrPem = $hcm.GenerateCertificateSigningRequest([bool](Test-IsIp $h.Name)) }
                    $info = Get-CsrInfo $csrPem
                    if ($info.CommonName -ne $h.Name) {
                        throw "the host wrote a CSR for '$($info.CommonName)', but vCenter knows it as $($h.Name). Make the host's own name match (KB 397317), then run again"
                    }
                    [System.IO.File]::WriteAllText($h.Folder.CsrPath, $csrPem.Replace("`r`n", "`n"), (New-Object System.Text.UTF8Encoding $false))
                    $note = ''
                    if (-not (Test-NameIn $h.Name $info.Dns $info.Ip)) { $note = " (it has no Subject Alternative Name for $($h.Name); make sure your CA adds DNS=$($h.Name))" }
                    Write-Host "$tag wrote $($h.Folder.CsrPath)$note"
                    $h.Result = 'csr written'
                    continue
                }
                elseif ($h.Action -eq 'install') {
                    $leaf = $h.Folder.Leaf
                    if ($mode -ne 'standalone') {
                        $lacking = @($h.Peers | Where-Object { -not $refreshed.ContainsKey($_.Name) })
                        if ($lacking.Count) {
                            Write-Host "$tag refreshing CA certificates on $(@($lacking | ForEach-Object { $_.Name }) -join ', ')"
                            Wait-VcTask $vc ($certMgr.CertMgrRefreshCACertificatesAndCRLs_Task(@($lacking | ForEach-Object { $_.Ref }))) $script:TaskTimeout
                            foreach ($p in $lacking) { $refreshed[$p.Name] = $true; $caCache.Remove($p.Name) }
                        }
                        $mine = & $readCa $h
                        if ($mine.Error) { throw "refused, nothing was changed: cannot read the host's CA certificates ($($mine.Error))" }
                        $check = Get-ChainCheck $leaf $h.Folder.Extra $mine.List $now
                        if (@($check.Problems).Count) { throw ('refused, nothing was changed: ' + (@($check.Problems) -join '; ') + '. Add the CA chain to vCenter (README), then run again') }
                        $peers = @($h)
                        if ($h.Cluster) { $peers = @($everyHost | Where-Object { $_.ClusterRef -eq $h.ClusterRef -and $_.Connected }) }
                        foreach ($p in $peers) {
                            $theirs = & $readCa $p
                            if ($theirs.Error) { throw "refused, nothing was changed: cannot read the CA certificates of $($p.Name), in the same cluster ($($theirs.Error))" }
                            if (& $lacksCa $p $check.Cas) { throw "refused, nothing was changed: $($p.Name), in the same cluster, does not list the new CA chain even after a refresh" }
                        }
                    }
                    $hcm = Get-View -Server $vc -Id $h.HcmRef
                    $leafPem = "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($leaf.RawData, 'InsertLineBreaks').Replace("`r`n", "`n") + "`n-----END CERTIFICATE-----`n"
                    Write-Host "$tag installing $(Split-Path -Leaf $h.Folder.SignedPath) (issued by $(Get-IssuerLabel $leaf), expires $(Format-Day $leaf.NotAfter))"
                    $hcm.InstallServerCertificate($leafPem)
                    try { $hcm.NotifyAffectedServices([string[]]@()) }
                    catch { throw "the certificate is installed, but the host did not take the notice to start using it ($($_.Exception.Message)): restart the management agents on the host, then run again to check" }
                    $after = Wait-NewCertificate $vc $h.Ref $before.Cert.Thumbprint $leaf.Thumbprint $script:SettleTimeout
                    if (-not $after.Done) {
                        if ($after.State -ne 'connected') { throw "the certificate is installed but the host is $($after.State) after $script:SettleTimeout s; check that vCenter trusts its CA chain, then reconnect the host" }
                        throw 'the certificate is installed but vCenter still shows the old one; disconnect and reconnect the host (KB 410036)'
                    }
                }

                $h.NewCert = $after.Cert
                $served = Test-Served $h.Name $after.Cert.Thumbprint
                if ($served -eq 'old') { throw "vCenter shows the new certificate, but port 443 still serves the old one after $script:ServeTimeout s: restart the management agents on the host" }
                $servedText = 'port 443 serves it'
                if ($served -eq 'unreachable') { $servedText = 'port 443 not reachable from here' }
                Write-Host "$tag done: expires $(Format-Day $after.Cert.NotAfter), issued by $(Get-IssuerLabel $after.Cert); $servedText"
                $h.Result = 'done'
            }
            catch {
                $h.Result = 'failed'
                $h.Reason = $_.Exception.Message
                Write-Host "$tag FAILED: $($_.Exception.Message)" -ForegroundColor Red
                $failed = $true
            }
        }
        $stopped = @($work | Where-Object { $_.Result -eq 'not attempted' })
        $changed = @($work | Where-Object { $_.Result -eq 'done' })
        $csrs = @($work | Where-Object { $_.Result -eq 'csr written' })
        Write-Host ''
        if ($changed.Count) { Write-Host "$($changed.Count) certificate(s) replaced and verified." }
        if ($csrs.Count) { Write-Host "$($csrs.Count) CSR(s) written. Have them signed, save each certificate next to its CSR as <host>.crt, then run the same command again." }
        if ($failed) {
            $more = ''
            if ($stopped.Count) { $more = " $($stopped.Count) host(s) not attempted." }
            Write-Host "Stopped at the failure.$more" -ForegroundColor Red
        }
    }

    foreach ($h in $hosts) {
        $o = [ordered]@{
            Host        = $h.Name
            Cluster     = $h.Cluster
            State       = $h.State
            Expires     = ''
            Issuer      = $h.Issuer
            Action      = $h.Action
            Result      = $h.Result
            Reason      = $h.Reason
            NewExpires  = ''
            NewIssuer   = ''
            Thumbprint  = ''
        }
        if ($h.Cert) { $o.Expires = Format-Day $h.NotAfter; $o.Thumbprint = $h.Cert.Thumbprint }
        if ($h.IsVmca) { $o.Issuer = 'VMCA' }
        if ($h.NewCert) { $o.NewExpires = Format-Day $h.NewCert.NotAfter; $o.NewIssuer = Get-IssuerLabel $h.NewCert; $o.Thumbprint = $h.NewCert.Thumbprint }
        [void]$results.Add((New-Object psobject -Property $o))
    }
}
finally {
    if ($ours -and $vc) { Disconnect-VIServer -Server $vc -Confirm:$false -ErrorAction SilentlyContinue }
}

if ($PassThru) { $results }
if ($failed) { exit 1 }
