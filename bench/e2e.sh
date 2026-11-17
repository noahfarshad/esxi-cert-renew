#!/bin/bash
# The rehearsal: Update-EsxiCertificate.ps1 run end to end against certsim, a vCenter
# simulator that fails the way Broadcom's knowledge base says vCenter and ESXi fail.
#
#   bench/e2e.sh
#
# Needs Linux with unprivileged user namespaces, Go 1.25 or later, PowerShell 7 with
# PowerCLI, and openssl. It runs inside its own network namespace, where the names in
# bench/hosts resolve to loopback addresses and port 443 can be bound without root:
# nothing here touches the machine's network, and nothing leaves it.
#
#   PWSH=/path/to/pwsh           another PowerShell than the one on PATH
#   BENCH=/path/to/scratch       where the simulator binary, logs and certificates go
#                                (default: a new folder under $TMPDIR or /tmp)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
TOOL=$HERE/../Update-EsxiCertificate.ps1
PWSH=${PWSH:-pwsh}

if [ "${1:-}" != "--inside" ]; then
    BENCH=${BENCH:-$(mktemp -d "${TMPDIR:-/tmp}/esxi-cert-bench.XXXXXX")}
    mkdir -p "$BENCH/log" "$BENCH/ca" "$BENCH/work" || exit 1
    echo "building certsim into $BENCH"
    (cd "$HERE/certsim" && go build -o "$BENCH/certsim" .) || exit 1
    export BENCH
    exec unshare --user --map-root-user --net --mount sh -c \
        'ip link set lo up && mount --bind "$1" /etc/hosts && shift && exec "$@"' ns "$HERE/hosts" "$0" --inside
fi

cd "$BENCH" || exit 1
W=$BENCH/work/$(date +%Y%m%d-%H%M%S); mkdir -p "$W"
pass=0; fail=0; SIM=""; NAME=""

sim() {     # sim <scenario> [certsim flags...]: one simulator at a time
    NAME=$1; shift
    [ -n "$SIM" ] && kill "$SIM" 2>/dev/null && wait "$SIM" 2>/dev/null
    local listen=127.0.0.2:443 tls=-host-tls
    case " $* " in *" -esx "*) listen=127.0.1.10:443; tls= ;; esac
    "$BENCH/certsim" -l $listen $tls -out "$BENCH/ca/$NAME" "$@" > "$BENCH/log/$NAME.log" 2>&1 &
    SIM=$!
    for _ in $(seq 1 30); do grep -q "certsim ready" "$BENCH/log/$NAME.log" && return 0; sleep 0.5; done
    echo "certsim did not start:"; tail -5 "$BENCH/log/$NAME.log"; exit 1
}
sign() {    # sign <csr> <out> <san> [days]: the scenario's issuing CA signs a CSR
    local ext=$W/ext.$RANDOM
    printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" > "$ext"
    openssl x509 -req -in "$1" -CA "$BENCH/ca/$NAME/custom-int.pem" -CAkey "$BENCH/ca/$NAME/custom-int.key" -CAcreateserial \
        -days "${4:-730}" -sha256 -extfile "$ext" -out "$2" 2>/dev/null
}
run() {     # run "<arguments>": the script, as an administrator would run it
    timeout 900 "$PWSH" -NoLogo -NoProfile -File "$HERE/invoke.ps1" -Server "${SERVER:-vcsa01.example.com}" \
        -Tool "${RUNTOOL:-$TOOL}" -ToolArgs "$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
}
expect() { if grep -q -E -- "$2" <<<"$OUT"; then pass=$((pass+1)); echo "  ok    $1"; else fail=$((fail+1)); echo "  FAIL  $1  (wanted: $2)"; echo "$OUT" | tail -12 | sed 's/^/        | /'; fi; }
reject() { if grep -q -E -- "$2" <<<"$OUT"; then fail=$((fail+1)); echo "  FAIL  $1  (did not want: $2)"; else pass=$((pass+1)); echo "  ok    $1"; fi; }
logexpect() { if grep -q -E -- "$2" "$BENCH/log/$NAME.log"; then pass=$((pass+1)); echo "  ok    $1"; else fail=$((fail+1)); echo "  FAIL  $1"; fi; }
logreject() { if grep -q -E -- "$2" "$BENCH/log/$NAME.log"; then fail=$((fail+1)); echo "  FAIL  $1"; else pass=$((pass+1)); echo "  ok    $1"; fi; }

# A copy with short waits, for the scenarios where a host never comes back.
sed -e 's/^\$script:SettleTimeout = 300 /$script:SettleTimeout = 15 /' -e 's/^\$script:ServeTimeout = 120 /$script:ServeTimeout = 12 /' "$TOOL" > "$W/short.ps1"
grep -q 'SettleTimeout = 15 ' "$W/short.ps1" && grep -q 'ServeTimeout = 12 ' "$W/short.ps1" || { echo "could not shorten the waits"; exit 1; }

echo "vmca mode"; sim vmca -mode vmca -flap 2s
OUT=$(run "")
expect 'plan: esx01 would renew' 'esx01.example.com .*WOULD renew through VMCA: 20 days left'
expect 'plan: esx03 in maintenance mode is skipped' 'esx03.example.com .*SKIP: 10 days left, but in maintenance mode'
expect 'plan: esx05 with a CA certificate is never replaced, issuer named' "esx05.example.com .*SKIP: 25 days left, but issued by 'Example Issuing CA 1', not VMCA"
expect 'plan: disconnected esx06 is skipped' 'esx06.example.com .*SKIP: not connected'
expect 'plan: 2 hosts to change' '2 host\(s\) to change'
OUT=$(echo "$OUT" | tr '\n' ' ')
expect 'plan: the host outside a cluster comes last' 'esx09.example.com .* esx08.example.com'
logreject 'plan changed nothing' 'renewed|refreshed'
OUT=$(run "-Cluster cl01 -Commit -PassThru | Format-Table Host,Result,NewExpires,NewIssuer -AutoSize | Out-String -Width 200 | Write-Host")
expect 'commit: esx01 done, port 443 serves the new certificate' 'esx01.example.com: done: expires 20[3-9][0-9]-[0-9-]+, issued by VMCA; port 443 serves it'
expect 'commit: esx04 done' 'esx04.example.com: done: .*port 443 serves it'
expect 'commit: verified' '2 certificate\(s\) replaced and verified'
expect 'commit: PassThru objects' 'esx01.example.com +done +20[3-9][0-9]-[0-9-]+ +VMCA'
expect 'commit: exit code 0' 'exit=0'
logexpect 'sim: esx01 renewed' 'esx01.example.com: renewed through VMCA'
logreject 'sim: esx03 in maintenance mode untouched' 'esx03.example.com: renew'
OUT=$(run "")
expect 'rerun: esx01 now ok' 'esx01.example.com .*ok, 18[0-9][0-9] days left'
OUT=$(run "-VMHost 'esx07*' -All -Commit")
expect '-All renews a host that is not due' 'esx07.example.com: done'
OUT=$(run "-VMHost nosuch")
expect 'no such host is an error' "No host matches 'nosuch'"
OUT=$(run "-CertFolder $W/none")
expect 'vmca mode with -CertFolder is an error' 'vCenter is in vmca mode; -CertFolder is for custom mode'
OUT=$(run "-CertFolder $W/none -Subject 'O=Example, C=US'")
expect 'a short -Subject is refused before anything else' '-Subject needs all of C, ST, L, O and OU'

echo "VMCA root expiring first"; sim rootsoon -mode vmca -vmca-root-days 10 -flap 1s
OUT=$(run "")
expect 'plan warns that a renewal would not extend' "esx01.example.com .*but VMCA's CA certificate on its list expires"
OUT=$(run "-Commit")
expect 'refused before any change' "esx01.example.com: FAILED: nothing was changed: VMCA's CA certificate expires"
expect 'stopped, the rest not attempted' 'Stopped at the failure. 1 host\(s\) not attempted'
expect 'exit code 1' 'exit=1'
logreject 'sim: no renewal happened' 'renewed through VMCA'

echo "VMCA root that would buy a few days"; sim rootbuys -mode vmca -vmca-root-days 25 -flap 1s
OUT=$(run "-VMHost esx04.example.com -Commit")
expect 'a renewal that stays inside the -Days window is refused' "esx04.example.com: FAILED: nothing was changed: VMCA's CA certificate expires"
logreject 'sim: no renewal happened' 'renewed through VMCA'

echo "VMCA root shorter than a full renewal"; sim root400 -mode vmca -vmca-root-days 400 -flap 1s
OUT=$(run "-VMHost esx01.example.com -Commit")
expect 'plan says where the new certificate will end' "esx01.example.com .*the new certificate ends 20[0-9-]+ with VMCA's CA certificate"
expect 'renewed, ending with the root' 'esx01.example.com: done: expires 20[0-9-]+, issued by VMCA'

echo "VMCA under another name"; sim renamed -mode vmca -vmca-cn 'Example VMCA' -flap 1s
OUT=$(run "-VMHost esx01.example.com")
expect 'an unrecognised VMCA is not renewed over, and is named' "esx01.example.com .*SKIP: 20 days left, but issued by 'Example VMCA', not VMCA"
OUT=$(run "-VMHost esx01.example.com -VmcaIssuer 'Example VMCA' -Commit")
expect '-VmcaIssuer: renewed' 'esx01.example.com: done: expires 20[3-9][0-9]-[0-9-]+, issued by VMCA; port 443 serves it'

echo "thumbprint mode"; sim thumb -mode thumbprint
OUT=$(run "-Cluster cl01 -Commit")
expect 'nothing is done' 'esx01.example.com .*thumbprint mode: vCenter does not manage host certificates'
expect 'nothing to do' 'Nothing to do'

echo "custom mode"; sim custom -mode custom -flap 1s; C=$W/custom; CA=$BENCH/ca/custom
OUT=$(run "")
expect 'without -CertFolder the plan says what is needed' 'esx01.example.com .*still on a VMCA certificate: give -CertFolder to write its CSR'
OUT=$(run "-CertFolder $C -Subject 'C=US, ST=Virginia, L=Reston, O=Example, OU=Infrastructure' -Commit")
expect 'round 1: 7 CSRs' '7 CSR\(s\) written'
expect 'round 1: ESXi 8.0.2 skipped' 'esx04.example.com .*SKIP: still on a VMCA certificate, but ESXi 8.0.2'
OUT=$(openssl req -in "$C/esx01.example.com.csr" -noout -subject -nameopt RFC2253 2>&1)
expect 'round 1: the CSR carries -Subject and the host name' 'CN=esx01.example.com,OU=Infrastructure,O=Example,(L=Reston,ST=Virginia|ST=Virginia,L=Reston),C=US'
OUT=$(run "-CertFolder $C -Commit")
expect 'round 1 again: nothing rewritten, hosts wait' 'esx01.example.com .*waiting: for esx01.example.com.crt, signed from esx01.example.com.csr'
reject 'round 1 again: no new CSR' 'generating a CSR'
sign "$C/esx01.example.com.csr" "$C/esx01.example.com.crt" DNS:esx01.example.com
sign "$C/esx02.example.com.csr" "$C/esx02.example.com.crt" DNS:esx99.example.com
sign "$C/esx05.example.com.csr" "$W/x5.pem" DNS:esx05.example.com && openssl crl2pkcs7 -nocrl -certfile "$W/x5.pem" -certfile "$CA/custom-int.pem" -outform DER -out "$C/esx05.example.com.p7b"
sign "$C/esx09.example.com.csr" "$W/x9.pem" DNS:esx09.example.com && cat "$W/x9.pem" "$CA/custom-int.pem" "$CA/custom-root.pem" > "$C/esx09.example.com.pem"
sign "$C/esx07.example.com.csr" "$C/esx07.example.com.crt" DNS:esx07.example.com 10
# A Microsoft CA's base-64 "certificate chain" download: PKCS#7 inside CERTIFICATE lines.
sign "$C/esx08.example.com.csr" "$W/x8.pem" DNS:esx08.example.com && openssl crl2pkcs7 -nocrl -certfile "$W/x8.pem" -certfile "$CA/custom-int.pem" -certfile "$CA/custom-root.pem" -outform PEM | sed 's/PKCS7-----/CERTIFICATE-----/' > "$C/esx08.example.com.cer"
OUT=$(run "-CertFolder $C")
expect 'round 2 plan: esx01 install, cl01 refresh first' 'esx01.example.com .*WOULD install: esx01.example.com.crt, issued by Example Issuing CA 1.*first refresh CA certificates on the 4 host'
expect 'round 2 plan: wrong SAN refused' 'esx02.example.com .*SKIP: esx02.example.com.crt: its Subject Alternative Name does not include esx02.example.com'
expect 'round 2 plan: short-lived certificate refused' 'esx07.example.com .*SKIP: esx07.example.com.crt: it expires .*within 30 days'
expect 'round 2 plan: .p7b accepted' 'esx05.example.com .*WOULD install: esx05.example.com.p7b'
expect 'round 2 plan: Microsoft-style chain download accepted' 'esx08.example.com .*WOULD install: esx08.example.com.cer'
expect 'round 2 plan: esx03 waiting' 'esx03.example.com .*waiting: for esx03.example.com.crt'
logreject 'plan refreshed nothing' 'refreshed'
OUT=$(run "-CertFolder $C -Commit")
expect 'round 2 commit: 4 installed' '4 certificate\(s\) replaced and verified'
expect 'round 2 commit: cl01 peers refreshed' 'refreshing CA certificates on esx01.example.com, esx02.example.com, esx03.example.com, esx04.example.com'
expect 'round 2 commit: port 443 serves the CA certificate' 'esx01.example.com: done: expires 20[0-9-]+, issued by Example Issuing CA 1; port 443 serves it'
logexpect 'sim: services notified the way PowerCLI does it' 'esx01.example.com: services notified \(0 named\)'
logreject 'sim: no host lost trust' 'not trusted by vCenter'
OUT=$(run "-CertFolder $C")
expect 'rerun: installed hosts ok' 'esx01.example.com .*installed from esx01.example.com.crt'
# A second CSR for a host makes the first one worthless: the host must refuse its certificate.
OUT=$(run "-CertFolder $W/custom2 -VMHost esx03.example.com -Commit")
expect 'a second CSR for esx03, in another folder' '1 CSR\(s\) written'
sign "$C/esx03.example.com.csr" "$C/esx03.example.com.crt" DNS:esx03.example.com
OUT=$(run "-CertFolder $C -VMHost esx03.example.com -Commit")
expect 'the certificate for the superseded CSR is refused by the host' "esx03.example.com: FAILED: .*don't match"
logreject 'sim: esx03 kept its certificate' 'esx03.example.com: services notified'

echo "custom mode, vCenter does not trust the CA"; sim untrusted -mode custom -trust-custom=false -flap 1s; C=$W/untrusted
OUT=$(run "-CertFolder $C -VMHost esx01.example.com -Commit")
sign "$C/esx01.example.com.csr" "$C/esx01.example.com.crt" DNS:esx01.example.com
OUT=$(run "-CertFolder $C -VMHost esx01.example.com -Commit")
expect 'refused after the refresh, nothing changed' 'FAILED: refused, nothing was changed'
expect 'all cl01 peers refreshed despite -VMHost' 'refreshing CA certificates on esx01.example.com, esx02.example.com, esx03.example.com, esx04.example.com'
logreject 'sim: nothing installed' 'not trusted by vCenter|services notified'

echo "custom mode, a host that calls itself something else"; sim wrongname -mode custom -wrong-name esx02.example.com
OUT=$(run "-CertFolder $W/wrongname -Cluster cl01")
expect 'the mismatch is refused in the plan (KB 397317)' 'esx02.example.com .*SKIP: .*the host calls itself esx02-old.example.com while vCenter knows it as esx02.example.com'

echo "custom mode, the agents never pick the certificate up"; sim staleserve -mode custom -stale-serve esx01.example.com; C=$W/staleserve
OUT=$(run "-CertFolder $C -VMHost esx01.example.com -Commit")
sign "$C/esx01.example.com.csr" "$C/esx01.example.com.crt" DNS:esx01.example.com
OUT=$(RUNTOOL=$W/short.ps1 run "-CertFolder $C -VMHost esx01.example.com -Commit")
expect 'port 443 still on the old certificate is a failure' 'esx01.example.com: FAILED: vCenter shows the new certificate, but port 443 still serves the old one after 12 s'

echo "custom mode, vCenter keeps showing the old certificate"; sim stalevc -mode custom -stale-vc esx01.example.com; C=$W/stalevc
OUT=$(run "-CertFolder $C -VMHost esx01.example.com -Commit")
sign "$C/esx01.example.com.csr" "$C/esx01.example.com.crt" DNS:esx01.example.com
OUT=$(RUNTOOL=$W/short.ps1 run "-CertFolder $C -VMHost esx01.example.com -Commit")
expect 'the reconnect advice from KB 410036' 'esx01.example.com: FAILED: the certificate is installed but vCenter still shows the old one; disconnect and reconnect the host \(KB 410036\)'

echo "straight to an ESXi host"; sim esx -esx; C=$W/esx
OUT=$(SERVER=esx10.example.com run "")
expect 'plan: connected directly' 'ESXi esx10.example.com \(8.0.3\), connected directly'
OUT=$(SERVER=esx10.example.com run "-CertFolder $C -Commit")
expect 'CSR written' '1 CSR\(s\) written'
sign "$C/esx10.example.com.csr" "$C/esx10.example.com.crt" DNS:esx10.example.com
OUT=$(SERVER=esx10.example.com run "-CertFolder $C -Commit")
expect 'installed, and the host itself serves it' 'esx10.example.com: done: expires 20[0-9-]+, issued by Example Issuing CA 1; port 443 serves it'
reject 'no CA refresh on a standalone host' 'refreshing CA certificates'
sim esxmanaged -esx -managed-by 192.0.2.5
OUT=$(SERVER=esx10.example.com run "-CertFolder $W/esxmanaged -Commit")
expect 'a host a vCenter manages is left alone' 'esx10.example.com .*managed by vCenter 192.0.2.5: run this against that vCenter'
sim esxold -esx -esx-version 8.0.2
OUT=$(SERVER=esx10.example.com run "-CertFolder $W/esxold -Commit")
expect 'ESXi 8.0.2 is left alone' 'esx10.example.com .*SKIP: 20 days left, but ESXi 8.0.2'

echo "a host that does not come back"; sim flap -mode vmca -flap 60s
OUT=$(RUNTOOL=$W/short.ps1 run "-Cluster cl01 -Commit")
expect 'failure reported' 'FAILED: the renewal ran but the host is notResponding after 15 s'
expect 'stopped' 'Stopped at the failure. 1 host\(s\) not attempted'

[ -n "$SIM" ] && kill "$SIM" 2>/dev/null
echo; echo "e2e: $pass passed, $fail failed  (logs and certificates: $BENCH)"
[ $fail -eq 0 ]
