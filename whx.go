package whox

import (
	"fmt"
	"github.com/iami317/hubur"
	"github.com/iami317/logx"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func Run(resource string) (domain DomainInfo, asnInfo IP, cert Cert) {
	var ipStr string
	var err error
	if hubur.IsDomain(resource) {
		domain, err = queryDomain(resource)
		ips, err := net.LookupHost(resource)
		if err != nil {
			logx.Errorf("获取域名(%v)的 ip 地址失败：%v", resource, err)
		}
		if len(ips) > 0 {
			logx.Infof("获取到 域名(%v)的 ip 地址：%v", resource, ips)
			domain.DomainIp = ips[0]
		}
		//queryIcp(domain.DomainName)
	}

	if len(ipStr) > 0 {
		asnInfo, err = LookupIP(ipStr)
		if err != nil {
			logx.Error(err)
		}
		cert = queryCert(ipStr)
	}
	return domain, asnInfo, cert
}
func queryCert(ipStr string) Cert {
	cert := NewCert(ipStr)
	return Cert{
		Subject:            cert.Subject,
		DomainName:         cert.DomainName,
		SignatureAlgorithm: cert.SignatureAlgorithm,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm,
		Issuer:             cert.Issuer,
		SANs:               cert.SANs,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
	}
}

// QueryIP 函数用于处理用于查询给定 IP 的 RDAP 信息的 HTTP 请求。
func queryIP(ipStr string) (result IPInfo, err error) {
	ip := net.ParseIP(ipStr)
	var tld string
	for cidr := range TLDToRdapServer {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// If the key cannot be parsed as a CIDR, skip this key
			continue
		}

		if ipNet.Contains(ip) {
			tld = cidr
			break
		}
	}

	// Query the RDAP information for the IP
	logx.Debugf("tld:%v ip:%v", tld, ip.String())
	queryResult, err := RDAPQueryIP(ipStr, tld)
	logx.Debugf("queryResult:%v --- err:%v", queryResult, err)
	if err != nil {
		if err.Error() == "resource not found" {
			return result, fmt.Errorf("Resource not found")
		} else if err.Error() == "the registry denied the query" {
			return result, fmt.Errorf("The registry denied the query")
		} else {
			return result, fmt.Errorf("error:%v", err)
		}
	}

	// Parse the RDAP response
	ipInfo, err := ParseRDAPResponseforIP(queryResult)
	if err != nil {
		return result, fmt.Errorf("ParseRDAPResponseforIP error:%v", err)
	}
	return ipInfo, nil
}

// queryASN 函数用于处理用于查询给定 ASN（自治系统编号）的 RDAP 信息的 HTTP 请求。
func queryASN(asnStr string) (result ASNInfo, err error) {
	// Parse the ASN
	asn := strings.TrimPrefix(asnStr, "asn")
	if asn == asnStr {
		asn = strings.TrimPrefix(asnStr, "as")
	}
	asnInt, err := strconv.Atoi(asn)
	if err != nil {
		return result, err
	}

	// Find the corresponding TLD from the TLDToRdapServer map
	var tld string
	for rangeStr := range TLDToRdapServer {
		if !strings.Contains(rangeStr, "-") {
			continue
		}
		rangeParts := strings.Split(rangeStr, "-")
		if len(rangeParts) != 2 {
			continue
		}
		lower, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			continue
		}
		upper, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			continue
		}
		if asnInt >= lower && asnInt <= upper {
			tld = rangeStr
			break
		}
	}

	queryresult, err := RDAPQueryASN(asn, tld)
	if err != nil {
		return result, err
	}

	// Parse the RDAP response
	asnInfo, err := ParseRDAPResponseforASN(queryresult)
	if err != nil {
		return result, err
	}
	return asnInfo, nil
}

// queryDomain 函数用于处理查询给定域的 RDAP（注册数据访问协议）或 WHOIS 信息的 HTTP 请求。
func queryDomain(resource string) (result DomainInfo, err error) {
	// 将域名转换为Punycode编码（支持IDN域名）
	punycodeDomain, err := idna.ToASCII(resource)
	if err != nil {
		return result, fmt.Errorf("Invalid domain name:%v", resource)
	}
	resource = punycodeDomain
	// 获取该域的TLD（顶级域）
	tld, _ := publicsuffix.PublicSuffix(resource)

	// If the TLD is not as expected (e.g., "com.cn"), read the domain from right to left and take the part to the right of the first dot as the TLD
	if strings.Contains(tld, ".") {
		parts := strings.Split(tld, ".")
		tld = parts[len(parts)-1]
	}

	// Get the main domain
	mainDomain, _ := publicsuffix.EffectiveTLDPlusOne(resource)
	if mainDomain == "" {
		mainDomain = resource
	}
	resource = mainDomain
	domain := resource
	var queryResult string

	// 如果 TLD 的 RDAP 服务器已知，请查询域的 RDAP 信息
	if rdapServer, ok := TLDToRdapServer[tld]; ok {
		queryResult, err = RDAPQuery(domain, tld)
		if err != nil {
			return result, err
		}
		domainInfo, err := ParseRDAPResponseforDomain(queryResult)
		if err != nil {
			return result, err
		}
		if len(rdapServer) > 0 {
			u, _ := url.Parse(rdapServer)
			domainInfo.WhoisServer = u.Host
		}

		return domainInfo, nil
		// 如果已知 TLD 的 WHOIS 服务器，请查询该域的 WHOIS 信息
	} else if whoisServer, ok := TLDToWhoisServer[tld]; ok {
		// Use the parsing function corresponding to the TLD to parse the WHOIS data
		var domainInfo DomainInfo
		queryResult, err = Whois(domain, tld)
		if err != nil {
			return result, err
		}

		if parseFunc, ok := whoisParsers[tld]; ok {
			domainInfo, err = parseFunc(queryResult, domain)
			if err != nil {
				return result, err
			}

			domainInfo.WhoisServer = whoisServer
			return domainInfo, nil
		}
	}
	return result, fmt.Errorf("No WHOIS or RDAP server known for TLD: %v", tld)
}
