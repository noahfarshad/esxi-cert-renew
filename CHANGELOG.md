# Changelog

## 1.0.0 - 2026-11-17

First release.

- vmca mode: renew ESXi host certificates through vCenter, one host at a time, plan by default. Leaves alone hosts that are not connected, in maintenance mode, or on a certificate from another CA, and refuses before any change when VMCA's CA certificate ends too soon for a renewal to help (KB 419417). `-VmcaIssuer` for a VMCA that is not called CA.
- custom mode: the host writes a CSR and keeps the key; signed certificates (`.crt`, `.cer`, `.pem`, `.p7b`) are checked for key, name, SAN, usages, signature, validity and chain, then installed through vCenter on ESXi 8.0 Update 3 and later. CA certificates are refreshed first on every host in the cluster that does not list the new chain. `-Subject` sets the organization fields of the CSR.
- Straight to an ESXi host that no vCenter manages: the custom workflow on that host.
- Every change is verified: connected again, the new certificate in vCenter, and port 443 serving it when reachable. The run stops at the first failure and exits 1.
- `-SelfTest`: 66 checks, no vCenter needed. `-PassThru` for a CSV of every host's certificate.
- `bench/`: a vCenter simulator with the certificate calls, and 68 end-to-end checks against it.
