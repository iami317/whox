package whois

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const defaultPort = "443"

var (
	SkipVerify     = true
	CipherSuite    = ""
	TimeoutSeconds = 3
	cipherSuites   = map[string]uint16{
		"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}
)

type Cert struct {
	IP                 string              `json:"-"`
	Port               string              `json:"-"`
	Subject            string              `json:"subject,omitempty" #:"主体"`
	DomainName         string              `json:"domain_name,omitempty" #:"域名"`
	SignatureAlgorithm string              `json:"signature_algorithm,omitempty" #:"签名哈希算法"`
	PublicKeyAlgorithm string              `json:"public_key_algorithm,omitempty" #:"公钥加密算法"`
	Issuer             string              `json:"issuer,omitempty" #:"颁发者"`
	SANs               []string            `json:"sans,omitempty"`
	NotBefore          string              `json:"not_before,omitempty" #:"开始时间(UTC)"`
	NotAfter           string              `json:"not_after,omitempty" #:"结束时间(UTC)"`
	Error              string              `json:"-"`
	certChain          []*x509.Certificate `json:"-"`
}

func (r *Cert) String() string {
	rBytes, _ := json.Marshal(r)
	return string(rBytes)
}

func SplitHostPort(hostport string) (string, string, error) {
	if strings.Contains(hostport, "://") {
		u, err := url.Parse(hostport)
		if err != nil {
			return "", "", err
		}
		hostport = u.Host
	}
	if !strings.Contains(hostport, ":") {
		return hostport, defaultPort, nil
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", "", err
	}

	if port == "" {
		port = defaultPort
	}
	return host, port, nil
}

func cipherSuite() ([]uint16, error) {
	if CipherSuite == "" {
		return nil, nil
	}

	var cs []uint16
	cs = []uint16{cipherSuites[CipherSuite]}
	if cs[0] == 0 {
		return nil, fmt.Errorf("%s is unsupported cipher suite or tls1.3 cipher suite.", CipherSuite)
	}
	return cs, nil
}

func tlsVersion() uint16 {
	if CipherSuite != "" {
		return tls.VersionTLS13
	}
	return 0
}

var serverCert = func(host, port string) ([]*x509.Certificate, string, error) {
	d := &net.Dialer{
		Timeout: time.Duration(TimeoutSeconds) * time.Second,
	}

	cs, err := cipherSuite()
	if err != nil {
		return []*x509.Certificate{{}}, "", err
	}

	conn, err := tls.DialWithDialer(d, "tcp", host+":"+port, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       cs,
		MaxVersion:         tlsVersion(),
	})
	if err != nil {
		return []*x509.Certificate{{}}, "", err
	}
	defer conn.Close()

	addr := conn.RemoteAddr()
	ip, _, _ := net.SplitHostPort(addr.String())
	cert := conn.ConnectionState().PeerCertificates

	return cert, ip, nil
}

func NewCert(hostport string) *Cert {
	host, port, err := SplitHostPort(hostport)
	if err != nil {
		return &Cert{DomainName: host, Error: err.Error()}
	}
	certChain, ip, err := serverCert(host, port)
	if err != nil {
		return &Cert{DomainName: host, Error: err.Error()}
	}
	cert := certChain[0]
	var loc *time.Location
	loc = time.UTC
	return &Cert{
		DomainName:         host,
		IP:                 ip,
		Port:               port,
		Subject:            cert.Subject.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		Issuer:             cert.Issuer.String(),
		SANs:               cert.DNSNames,
		NotBefore:          cert.NotBefore.In(loc).String(),
		NotAfter:           cert.NotAfter.In(loc).String(),
		Error:              "",
		certChain:          certChain,
	}
}

func (c *Cert) Detail() *x509.Certificate {
	return c.certChain[0]
}

func (c *Cert) CertChain() []*x509.Certificate {
	return c.certChain
}

type Certs []*Cert

var tokens = make(chan struct{}, 128)

func validate(s []string) error {
	if len(s) < 1 {
		return fmt.Errorf("Input at least one domain name.")
	}
	return nil
}

func NewCerts(s []string) (Certs, error) {
	if err := validate(s); err != nil {
		return nil, err
	}

	type indexer struct {
		index int
		cert  *Cert
	}

	ch := make(chan *indexer)
	for i, d := range s {
		go func(i int, d string) {
			tokens <- struct{}{}
			ch <- &indexer{i, NewCert(d)}
			<-tokens
		}(i, d)
	}

	certs := make(Certs, len(s))
	for range s {
		i := <-ch
		certs[i.index] = i.cert
	}
	return certs, nil
}

func (certs Certs) escapeStar() Certs {
	for _, cert := range certs {
		for i, san := range cert.SANs {
			cert.SANs[i] = strings.Replace(san, "*", "\\*", -1)
		}
	}
	return certs
}
