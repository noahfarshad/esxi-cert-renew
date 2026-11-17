// certsim is a vCenter simulator for rehearsing Update-EsxiCertificate.ps1.
//
// It is govmomi's vcsim plus the ESXi certificate calls stock vcsim does not implement,
// made to behave the way the vSphere API reference and Broadcom's knowledge base say
// vCenter and ESXi behave:
//
//   - CertMgrRefreshCertificates_Task (the vSphere Client's Renew): completes and changes
//     nothing for a host in maintenance mode (KB 390133), cuts the new certificate to the
//     VMCA root's expiry (KB 419417), and leaves the host notResponding for a moment
//     (KB 420313). It also refreshes the host's CA certificates (KB 426775).
//   - GenerateCertificateSigningRequest makes a new key on the host and forgets the one
//     from any earlier CSR. InstallServerCertificate takes only a certificate for that key.
//   - The host keeps serving its old certificate on port 443 until NotifyAffectedServices,
//     which only ESXi 8.0 Update 3 and later knows.
//   - A certificate vCenter does not trust disconnects the host.
//
// It is a test bench, not a model of vCenter: what it does not implement, it does not claim.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25/methods"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

type ca struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	pem  []byte
}

var (
	oidDC    = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	oidEmail = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func newCA(subject pkix.Name, notAfter time.Time, parent *ca) *ca {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               subject,
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		log.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &ca{cert: c, key: key, pem: pemCert(der)}
}

func (c *ca) issue(pub *rsa.PublicKey, subject pkix.Name, name string, notBefore, notAfter time.Time) []byte {
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter // a CA cannot issue past its own expiry (KB 419417)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		log.Fatal(err)
	}
	return pemCert(der)
}

func vmcaHostSubject(name string) pkix.Name {
	return pkix.Name{
		CommonName: name, Country: []string{"US"}, Province: []string{"California"}, Locality: []string{"Palo Alto"},
		Organization: []string{"VMware"}, OrganizationalUnit: []string{"VMware Engineering"},
		ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidEmail, Value: "vmca@vmware.com"}},
	}
}

type hostState struct {
	mu         sync.Mutex
	key        *rsa.PrivateKey
	pending    *rsa.PrivateKey
	cert       []byte // installed (config.certificate)
	served     []byte // what hostd serves on 443
	servedKey  *rsa.PrivateKey
	name       string
	staleServe bool // NotifyAffectedServices changes nothing (agents never pick the certificate up)
	staleVC    bool // vCenter does not show an installed certificate until a reconnect (KB 410036)
	caList     []string
	api        string
}

type world struct {
	mu      sync.Mutex
	vmca    *ca
	root    *ca
	inter   *ca
	trusted [][]byte // vCenter TRUSTED_ROOTS (PEM)
	hosts   map[string]*hostState
	model   *simulator.Model
	daysVal int
	flap    time.Duration
}

func (w *world) trustedPool() *x509.CertPool {
	p := x509.NewCertPool()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range w.trusted {
		p.AppendCertsFromPEM(b)
	}
	return p
}

func (w *world) trustedList() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := []string{}
	for _, b := range w.trusted {
		out = append(out, string(b))
	}
	return out
}

func (st *hostState) tlsCert() (*tls.Certificate, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	block, _ := pem.Decode(st.served)
	if block == nil || st.servedKey == nil {
		return nil, fmt.Errorf("no certificate")
	}
	return &tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: st.servedKey}, nil
}

// serve443 answers TLS handshakes with whatever the host serves right now.
func (st *hostState) serve443(addr string) {
	ln, err := tls.Listen("tcp", addr, &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return st.tlsCert() }})
	if err != nil {
		log.Fatalf("%s: %v", addr, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				time.Sleep(200 * time.Millisecond)
				_ = c.Close()
			}()
		}
	}()
}

func certInfo(pemBytes []byte) types.HostCertificateManagerCertificateInfo {
	block, _ := pem.Decode(pemBytes)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return types.HostCertificateManagerCertificateInfo{Status: "unknown"}
	}
	left := time.Until(c.NotAfter)
	status := "good"
	switch {
	case left <= 0:
		status = "expired"
	case left < 30*24*time.Hour:
		status = "expirationImminent"
	case left < 120*24*time.Hour:
		status = "expiringShortly"
	case left < 240*24*time.Hour:
		status = "expiring"
	}
	nb, na := c.NotBefore, c.NotAfter
	return types.HostCertificateManagerCertificateInfo{
		Issuer: c.Issuer.String(), Subject: c.Subject.String(), NotBefore: &nb, NotAfter: &na, Status: status,
	}
}

// ---- host certificate manager -------------------------------------------------

type HostCertMgr struct {
	mo.HostCertificateManager
	host *simulator.HostSystem
	st   *hostState
	w    *world
}

func hostFault(msg string) *soap.Fault {
	return simulator.Fault(msg, &types.HostConfigFault{})
}

func (m *HostCertMgr) csr(subject pkix.Name, dns []string) string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	m.st.mu.Lock()
	m.st.pending = key
	m.st.mu.Unlock()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject, DNSNames: dns}, key)
	if err != nil {
		log.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func (m *HostCertMgr) fqdn() string {
	if d, ok := m.host.Config.Network.DnsConfig.(*types.HostDnsConfig); ok && d.HostName != "" {
		if d.DomainName != "" {
			return d.HostName + "." + d.DomainName
		}
		return d.HostName
	}
	return m.host.Name
}

func (m *HostCertMgr) GenerateCertificateSigningRequest(ctx *simulator.Context, req *types.GenerateCertificateSigningRequest) soap.HasFault {
	log.Printf("%s: CSR, useIpAddressAsCommonName=%v", m.host.Name, req.UseIpAddressAsCommonName)
	cn := m.fqdn()
	if req.UseIpAddressAsCommonName {
		cn = "192.0.2.10"
	}
	pemText := m.csr(pkix.Name{CommonName: cn}, []string{cn})
	return &methods.GenerateCertificateSigningRequestBody{Res: &types.GenerateCertificateSigningRequestResponse{Returnval: pemText}}
}

func parseDN(dn string) pkix.Name {
	var n pkix.Name
	for _, part := range strings.Split(dn, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		v := strings.TrimSpace(kv[1])
		switch strings.ToUpper(strings.TrimSpace(kv[0])) {
		case "CN":
			n.CommonName = v
		case "O":
			n.Organization = append(n.Organization, v)
		case "OU":
			n.OrganizationalUnit = append(n.OrganizationalUnit, v)
		case "L":
			n.Locality = append(n.Locality, v)
		case "ST":
			n.Province = append(n.Province, v)
		case "C":
			n.Country = append(n.Country, v)
		}
	}
	return n
}

func (m *HostCertMgr) GenerateCertificateSigningRequestByDn(ctx *simulator.Context, req *types.GenerateCertificateSigningRequestByDn) soap.HasFault {
	log.Printf("%s: CSR by DN %q", m.host.Name, req.DistinguishedName)
	n := parseDN(req.DistinguishedName)
	pemText := m.csr(n, []string{n.CommonName})
	return &methods.GenerateCertificateSigningRequestByDnBody{Res: &types.GenerateCertificateSigningRequestByDnResponse{Returnval: pemText}}
}

func (m *HostCertMgr) InstallServerCertificate(ctx *simulator.Context, req *types.InstallServerCertificate) soap.HasFault {
	body := new(methods.InstallServerCertificateBody)
	block, _ := pem.Decode([]byte(req.Cert))
	if block == nil {
		body.Fault_ = hostFault("not a PEM certificate")
		return body
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		body.Fault_ = hostFault(err.Error())
		return body
	}
	m.st.mu.Lock()
	pending := m.st.pending
	m.st.mu.Unlock()
	if pending == nil {
		body.Fault_ = hostFault("no private key: generate a CSR first")
		return body
	}
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(pending.PublicKey.N) != 0 || pub.E != pending.PublicKey.E {
		body.Fault_ = hostFault("the certificate and key don't match")
		return body
	}
	pemLeaf := pemCert(leaf.Raw)
	log.Printf("%s: certificate installed (%s)", m.host.Name, leaf.Subject.CommonName)
	m.st.mu.Lock()
	m.st.key, m.st.pending, m.st.cert = pending, nil, pemLeaf
	m.st.mu.Unlock()
	if !m.st.staleVC {
		ctx.WithLock(m.host, func() { m.host.Config.Certificate = pemLeaf })
	}
	m.CertificateInfo = certInfo(pemLeaf)

	// vCenter checks the new certificate against TRUSTED_ROOTS; an untrusted one disconnects the host.
	inter := x509.NewCertPool()
	for _, t := range m.w.trustedList() {
		inter.AppendCertsFromPEM([]byte(t))
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: m.w.trustedPool(), Intermediates: inter, DNSName: m.host.Name}); err != nil {
		log.Printf("%s: installed certificate is not trusted by vCenter (%v): disconnecting", m.host.Name, err)
		go func() {
			time.Sleep(time.Second)
			ctx.WithLock(m.host, func() { m.host.Runtime.ConnectionState = types.HostSystemConnectionStateDisconnected })
		}()
	}
	body.Res = new(types.InstallServerCertificateResponse)
	return body
}

func (m *HostCertMgr) NotifyAffectedServices(ctx *simulator.Context, req *types.NotifyAffectedServices) soap.HasFault {
	body := new(methods.NotifyAffectedServicesBody)
	if m.st.api < "8.0.3" {
		body.Fault_ = simulator.Fault("method not supported by this host", &types.MethodNotFound{Receiver: m.Self, Method: "NotifyAffectedServices"})
		return body
	}
	m.st.mu.Lock()
	if !m.st.staleServe {
		m.st.served, m.st.servedKey = m.st.cert, m.st.key
	}
	m.st.mu.Unlock()
	log.Printf("%s: services notified (%d named)", m.host.Name, len(req.Services))
	body.Res = new(types.NotifyAffectedServicesResponse)
	return body
}

func (m *HostCertMgr) ListCACertificates(ctx *simulator.Context, req *types.ListCACertificates) soap.HasFault {
	m.st.mu.Lock()
	list := append([]string(nil), m.st.caList...)
	m.st.mu.Unlock()
	return &methods.ListCACertificatesBody{Res: &types.ListCACertificatesResponse{Returnval: list}}
}

func (m *HostCertMgr) ReplaceCACertificatesAndCRLs(ctx *simulator.Context, req *types.ReplaceCACertificatesAndCRLs) soap.HasFault {
	m.st.mu.Lock()
	m.st.caList = append([]string(nil), req.CaCert...)
	m.st.mu.Unlock()
	return &methods.ReplaceCACertificatesAndCRLsBody{Res: new(types.ReplaceCACertificatesAndCRLsResponse)}
}

// ---- vCenter certificate manager ----------------------------------------------

type CertMgr struct {
	mo.CertificateManager
	w *world
}

func (c *CertMgr) find(ctx *simulator.Context, ref types.ManagedObjectReference) (*simulator.HostSystem, *HostCertMgr) {
	h, _ := ctx.Map.Get(ref).(*simulator.HostSystem)
	if h == nil {
		return nil, nil
	}
	m, _ := ctx.Map.Get(*h.ConfigManager.CertificateManager).(*HostCertMgr)
	return h, m
}

func (c *CertMgr) CertMgrRefreshCertificatesTask(ctx *simulator.Context, req *types.CertMgrRefreshCertificates_Task) soap.HasFault {
	task := simulator.CreateTask(c, "refreshCertificates", func(t *simulator.Task) (types.AnyType, types.BaseMethodFault) {
		time.Sleep(1500 * time.Millisecond)
		for _, ref := range req.Host {
			h, m := c.find(ctx, ref)
			if h == nil {
				return nil, &types.ManagedObjectNotFound{Obj: ref}
			}
			if h.Runtime.ConnectionState != types.HostSystemConnectionStateConnected {
				return nil, &types.HostNotConnected{}
			}
			if h.Runtime.InMaintenanceMode {
				log.Printf("%s: renew requested in maintenance mode: task succeeds, certificate unchanged (KB 390133)", h.Name)
				continue
			}
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			now := time.Now()
			pemNew := c.w.vmca.issue(&key.PublicKey, vmcaHostSubject(h.Name), h.Name, now.Add(-24*time.Hour), now.Add(time.Duration(c.w.daysVal)*24*time.Hour))
			m.st.mu.Lock()
			m.st.key, m.st.cert, m.st.served, m.st.servedKey, m.st.pending = key, pemNew, pemNew, key, nil
			m.st.caList = c.w.trustedList() // Renew also refreshes the CA list (KB 426775)
			m.st.mu.Unlock()
			m.CertificateInfo = certInfo(pemNew)
			ctx.WithLock(h, func() {
				h.Config.Certificate = pemNew
				h.Runtime.ConnectionState = types.HostSystemConnectionStateNotResponding
			})
			hh := h
			go func() {
				time.Sleep(c.w.flap)
				ctx.WithLock(hh, func() { hh.Runtime.ConnectionState = types.HostSystemConnectionStateConnected })
			}()
			log.Printf("%s: renewed through VMCA", h.Name)
		}
		return nil, nil
	})
	return &methods.CertMgrRefreshCertificates_TaskBody{Res: &types.CertMgrRefreshCertificates_TaskResponse{Returnval: task.Run(ctx)}}
}

func (c *CertMgr) CertMgrRefreshCACertificatesAndCRLsTask(ctx *simulator.Context, req *types.CertMgrRefreshCACertificatesAndCRLs_Task) soap.HasFault {
	task := simulator.CreateTask(c, "refreshCACertificatesAndCRLs", func(t *simulator.Task) (types.AnyType, types.BaseMethodFault) {
		time.Sleep(500 * time.Millisecond)
		for _, ref := range req.Host {
			h, m := c.find(ctx, ref)
			if h == nil {
				return nil, &types.ManagedObjectNotFound{Obj: ref}
			}
			if h.Runtime.ConnectionState != types.HostSystemConnectionStateConnected {
				return nil, &types.HostNotConnected{}
			}
			m.st.mu.Lock()
			m.st.caList = c.w.trustedList()
			m.st.mu.Unlock()
			log.Printf("%s: CA certificates refreshed", h.Name)
		}
		return nil, nil
	})
	return &methods.CertMgrRefreshCACertificatesAndCRLs_TaskBody{Res: &types.CertMgrRefreshCACertificatesAndCRLs_TaskResponse{Returnval: task.Run(ctx)}}
}

// ---- inventory ------------------------------------------------------------------

// Loopback addresses the bench's /etc/hosts gives each name.
var hostAddr = map[string]string{
	"esx01.example.com": "127.0.1.1", "esx02.example.com": "127.0.1.2", "esx03.example.com": "127.0.1.3",
	"esx04.example.com": "127.0.1.4", "esx05.example.com": "127.0.1.5", "esx06.example.com": "127.0.1.6",
	"esx07.example.com": "127.0.1.7", "esx08.example.com": "127.0.1.8", "esx09.example.com": "127.0.1.9",
	"esx10.example.com": "127.0.1.10",
}

type hostSpec struct {
	sim, name, version, build, api string
	mm, down                       bool
	issuer                         string
	days                           int
}

var specs = []hostSpec{
	{"DC0_C0_H0", "esx01.example.com", "8.0.3", "24022510", "8.0.3.0", false, false, "vmca", 20},
	{"DC0_C0_H1", "esx02.example.com", "8.0.3", "24022510", "8.0.3.0", false, false, "vmca", 900},
	{"DC0_C0_H2", "esx03.example.com", "8.0.3", "24022510", "8.0.3.0", true, false, "vmca", 10},
	{"DC0_C0_H3", "esx04.example.com", "8.0.2", "22380479", "8.0.2.0", false, false, "vmca", 15},
	{"DC0_C1_H0", "esx05.example.com", "8.0.3", "24022510", "8.0.3.0", false, false, "custom", 25},
	{"DC0_C1_H1", "esx06.example.com", "8.0.3", "24022510", "8.0.3.0", false, true, "vmca", 5},
	{"DC0_C1_H2", "esx07.example.com", "9.0.0", "24755229", "9.0.0.0", false, false, "vmca", 40},
	{"DC0_C1_H3", "esx09.example.com", "8.0.3", "24022510", "8.0.3.0", false, false, "vmca", 50},
	{"DC0_H0", "esx08.example.com", "8.0.3", "24022510", "8.0.3.0", false, false, "vmca", 700},
}

func main() {
	addr := flag.String("l", "127.0.0.2:443", "listen address")
	out := flag.String("out", "", "directory for CA material the test harness signs with")
	apiFlag := flag.String("api-version", "8.0.3.0", "vCenter API version")
	mode := flag.String("mode", "vmca", "vpxd.certmgmt.mode")
	rootDays := flag.Int("vmca-root-days", 3650, "days until the VMCA root expires")
	trustCustom := flag.Bool("trust-custom", true, "custom root and intermediate are in vCenter TRUSTED_ROOTS")
	flap := flag.Duration("flap", 3*time.Second, "notResponding time after a VMCA renew")
	esxMode := flag.Bool("esx", false, "simulate one ESXi host, connected to directly")
	esxVersion := flag.String("esx-version", "8.0.3", "ESXi version in -esx mode")
	managedBy := flag.String("managed-by", "", "-esx: the vCenter address the host reports (empty: no vCenter)")
	wrongName := flag.String("wrong-name", "", "this host calls itself something other than its vCenter name")
	hostTLS := flag.Bool("host-tls", false, "serve each host's certificate on <its address>:443")
	vmcaCN := flag.String("vmca-cn", "CA", "common name of VMCA's CA certificate; anything but CA also drops the VMware OU")
	staleServe := flag.String("stale-serve", "", "this host keeps serving its old certificate after a notify")
	staleVC := flag.String("stale-vc", "", "vCenter does not show this host's installed certificate")
	flag.Parse()
	apiVersion := apiFlag

	now := time.Now()
	w := &world{daysVal: 1825, flap: *flap}
	vmcaSubject := pkix.Name{
		CommonName: "CA", Country: []string{"US"}, Province: []string{"California"},
		Organization: []string{"vcsa01.example.com"}, OrganizationalUnit: []string{"VMware Engineering"},
		ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidDC, Value: "vsphere"}, {Type: oidDC, Value: "local"}},
	}
	if *vmcaCN != "CA" {
		vmcaSubject = pkix.Name{CommonName: *vmcaCN, Country: []string{"US"}, Organization: []string{"Example"}, OrganizationalUnit: []string{"Example PKI"}}
	}
	w.vmca = newCA(vmcaSubject, now.Add(time.Duration(*rootDays)*24*time.Hour), nil)
	w.root = newCA(pkix.Name{CommonName: "Example Root CA", Organization: []string{"Example"}, Country: []string{"US"}}, now.Add(20*365*24*time.Hour), nil)
	w.inter = newCA(pkix.Name{CommonName: "Example Issuing CA 1", Organization: []string{"Example"}, Country: []string{"US"}}, now.Add(10*365*24*time.Hour), w.root)
	w.trusted = [][]byte{w.vmca.pem}
	if *trustCustom {
		w.trusted = append(w.trusted, w.root.pem, w.inter.pem)
	}
	if *out != "" {
		_ = os.MkdirAll(*out, 0o755)
		write := func(n string, b []byte) { _ = os.WriteFile(filepath.Join(*out, n), b, 0o600) }
		write("vmca-root.pem", w.vmca.pem)
		write("custom-root.pem", w.root.pem)
		write("custom-int.pem", w.inter.pem)
		write("custom-chain.pem", append(append([]byte{}, w.inter.pem...), w.root.pem...))
		write("custom-int.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(w.inter.key)}))
	}

	m := simulator.VPX()
	m.Cluster, m.ClusterHost, m.Host, m.Machine = 2, 4, 1, 0
	if *esxMode {
		m = simulator.ESX()
		m.Machine = 0
		api := *esxVersion + ".0"
		specs = []hostSpec{{"", "esx10.example.com", *esxVersion, "24022510", api, false, false, "vmca", 20}}
		apiVersion = &api
	}
	m.ServiceContent.About.ApiVersion = *apiVersion
	m.ServiceContent.About.Version = strings.Join(strings.Split(*apiVersion, ".")[:3], ".")
	m.ServiceContent.About.Build = "24022515"
	if err := m.Create(); err != nil {
		log.Fatal(err)
	}
	reg := m.Map()

	for _, e := range reg.All("ClusterComputeResource") {
		c := e.(*simulator.ClusterComputeResource)
		c.Name = map[string]string{"DC0_C0": "cl01", "DC0_C1": "cl02"}[c.Name]
	}
	var hostStates []*hostState
	byName := map[string]*simulator.HostSystem{}
	for _, e := range reg.All("HostSystem") {
		h := e.(*simulator.HostSystem)
		byName[h.Name] = h
		if *esxMode {
			byName[""] = h
		}
	}
	for _, s := range specs {
		h := byName[s.sim]
		if h == nil {
			log.Fatalf("no host %s", s.sim)
		}
		h.Name, h.Summary.Config.Name = s.name, s.name
		short, domain, _ := strings.Cut(s.name, ".")
		if s.name == *wrongName {
			short = short + "-old"
		}
		h.Config.Network.DnsConfig = &types.HostDnsConfig{HostName: short, DomainName: domain}
		prod := h.Config.Product
		prod.Version, prod.Build, prod.ApiVersion = s.version, s.build, s.api
		prod.FullName = "VMware ESXi " + s.version + " build-" + s.build
		h.Config.Product = prod
		h.Summary.Config.Product = &prod
		h.Runtime.InMaintenanceMode = s.mm
		if *esxMode {
			h.Summary.ManagementServerIp = *managedBy
		}
		if s.down {
			h.Runtime.ConnectionState = types.HostSystemConnectionStateDisconnected
		}
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		var certPEM []byte
		nb, na := now.Add(-(1825-time.Duration(s.days))*24*time.Hour), now.Add(time.Duration(s.days)*24*time.Hour+time.Hour)
		if s.issuer == "custom" {
			certPEM = w.inter.issue(&key.PublicKey, pkix.Name{CommonName: s.name, Organization: []string{"Example"}, Country: []string{"US"}}, s.name, nb, na)
		} else {
			// issued before any VMCA root change: not cut to the current root's expiry
			tmp := &ca{cert: w.vmca.cert, key: w.vmca.key}
			saved := tmp.cert.NotAfter
			tmp.cert.NotAfter = na.Add(24 * time.Hour)
			certPEM = tmp.issue(&key.PublicKey, vmcaHostSubject(s.name), s.name, nb, na)
			tmp.cert.NotAfter = saved
		}
		h.Config.Certificate = certPEM
		st := &hostState{key: key, cert: certPEM, served: certPEM, servedKey: key, name: s.name, api: s.api, caList: []string{string(w.vmca.pem)}}
		st.staleServe, st.staleVC = s.name == *staleServe, s.name == *staleVC
		hostStates = append(hostStates, st)
		hcm := &HostCertMgr{host: h, st: st, w: w}
		hcm.Self = *h.ConfigManager.CertificateManager
		hcm.CertificateInfo = certInfo(certPEM)
		reg.Put(hcm)
	}
	if !*esxMode {
		cm := &CertMgr{w: w}
		cm.Self = types.ManagedObjectReference{Type: "CertificateManager", Value: "certificateManager"}
		reg.Put(cm)

		om := reg.OptionManager()
		om.UpdateOptions(&types.UpdateOptions{ChangedValue: []types.BaseOptionValue{
			&types.OptionValue{Key: "vpxd.certmgmt.mode", Value: *mode},
			&types.OptionValue{Key: "vpxd.certmgmt.certs.daysValid", Value: "1825"},
			&types.OptionValue{Key: "VirtualCenter.FQDN", Value: "vcsa01.example.com"},
		}})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("UNHANDLED %s %s", r.Method, r.URL.Path)
		http.NotFound(rw, r)
	})
	m.Service.ServeMux = mux
	m.Service.Listen = &url.URL{Scheme: "https", Host: *addr}
	m.Service.TLS = new(tls.Config)
	if *esxMode {
		m.Service.TLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return hostStates[0].tlsCert() }
	}
	if *hostTLS && !*esxMode {
		for _, st := range hostStates {
			st.serve443(hostAddr[st.name] + ":443")
		}
	}
	s := m.Service.NewServer()
	fmt.Printf("certsim ready %s mode=%s api=%s esx=%v vmca-root-expires=%s\n", s.URL, *mode, *apiVersion, *esxMode, w.vmca.cert.NotAfter.Format("2006-01-02"))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	m.Remove()
}
