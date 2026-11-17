# The rehearsal bench

`e2e.sh` runs `Update-EsxiCertificate.ps1` end to end, 68 checks, against `certsim`, a vCenter simulator. Nothing here is needed to use the script.

## certsim

[govmomi](https://github.com/vmware/govmomi)'s `vcsim` answers the vSphere API well enough for PowerCLI to log in and list hosts, but it does not implement the certificate calls. `certsim` adds them, and makes them behave the way the vSphere API reference and Broadcom's knowledge base say vCenter and ESXi behave:

| Behaviour | Source |
|-----------|--------|
| Renew completes and changes nothing for a host in maintenance mode | KB 390133 |
| A VMCA certificate is cut to the VMCA root's expiry | KB 419417 |
| The host reads "Not responding" for a moment after a renewal | KB 420313 |
| Renew also refreshes the host's CA certificates | KB 426775 |
| A CSR makes a new key on the host and forgets the key of any earlier CSR; only a certificate for that key installs | vSphere API reference, `HostCertificateManager` |
| The host serves its old certificate on port 443 until `NotifyAffectedServices`, which only ESXi 8.0 Update 3 and later knows | vSphere API reference |
| A certificate that vCenter does not trust disconnects the host | vSphere documentation, "Replace the Default Certificate with a Custom Certificate" |

The fleet is nine hosts in two clusters, each one set up as a case: due, not due, in maintenance mode, on ESXi 8.0 Update 2, on a certificate from another CA, disconnected, on ESXi 9, outside a cluster. Flags turn on the rest: a VMCA root about to expire or under another name, a CA that vCenter does not trust, a host that calls itself by another name, a host whose agents never pick the certificate up, a vCenter that keeps showing the old one, a single ESXi host on its own.

Every host has a name and an address, and serves whatever certificate it holds on port 443. That takes a network of its own, so `e2e.sh` starts itself in a private network namespace where the names in `hosts` resolve to loopback addresses and port 443 can be bound without root. Nothing touches the machine's network and nothing leaves it.

## Run it

```sh
bench/e2e.sh
```

Needs Linux with unprivileged user namespaces, Go 1.25 or later, PowerShell 7 with PowerCLI (`Install-Module VCF.PowerCLI`), and openssl. `PWSH` names another PowerShell, `BENCH` another scratch folder. A run takes about five minutes and ends with:

```
e2e: 68 passed, 0 failed
```

Simulator logs and the certificates from the run stay in the scratch folder.

## What PowerCLI itself sends

The simulator logs what it is asked. Pointed at it, PowerCLI's own `New-VIMachineCertificateSigningRequest` and `Set-VIMachineCertificate -VMHost` leave this in the log, and the script leaves the same:

```
esx02.example.com: CSR, useIpAddressAsCommonName=false
esx01.example.com: CSR by DN "CN = esx01.example.com, C = US, L = Reston, ST = Virginia, O = Example, OU = Infrastructure"
esx01.example.com: certificate installed (esx01.example.com)
esx01.example.com: services notified (0 named)
```

## What it proves

That the script's decisions, its order of operations and its handling of every documented failure are right against a model built from the documentation. It does not prove vCenter: a model is only as good as what was written down. The first run on a real vCenter should still be the plan, then one host.
