
## 信息收集工具包
* 域名信息
* Asn信息
* 证书信息

```
whois.DomainInfo{
  WhoisServer:    "rdap.verisign.com",
  DomainName:     "GITHUB.COM",
  Registrant:     "",
  Registrar:      "MarkMonitor Inc.",
  RegistrarEmail: "",
  DomainStatus:   []string{
    "client delete prohibited",
    "client transfer prohibited",
    "client update prohibited",
  },
  CreationDate:       "2007-10-09T18:20:50Z",
  RegistryExpiryDate: "2024-10-09T18:20:50Z",
  NameServer:         []string{
    "DNS1.P08.NSONE.NET",
    "DNS2.P08.NSONE.NET",
    "DNS3.P08.NSONE.NET",
    "DNS4.P08.NSONE.NET",
    "NS-1283.AWSDNS-32.ORG",
    "NS-1707.AWSDNS-21.CO.UK",
    "NS-421.AWSDNS-52.COM",
    "NS-520.AWSDNS-01.NET",
  },
  DNSSec:             "unsigned",
  UpdatedDate:        "2022-09-07T09:10:44Z",
  RegistrarIANAID:    "292",
  DNSSecDSData:       "",
  LastUpdateOfRDAPDB: "2024-07-11T06:45:36Z",
}
whois.IP{
  ASNum:     8075,
  IP:        "20.205.243.166",
  IpVersion: "v4",
  BGPPrefix: "20.192.0.0/10",
  Country:   "US",
  Registry:  "arin",
  Allocated: "2017-10-18",
  ASName:    "MICROSOFT-CORP-MSN-AS-BLOCK, US",
}
whois.Cert{
  IP:                 "",
  Port:               "",
  Subject:            "CN=github.com",
  DomainName:         "20.205.243.166",
  SignatureAlgorithm: "ECDSA-SHA256",
  PublicKeyAlgorithm: "ECDSA",
  Issuer:             "CN=Sectigo ECC Domain Validation Secure Server CA,O=Sectigo Limited,L=Salford,ST=Greater Manchester,C=GB",
  SANs:               []string{
    "github.com",
    "www.github.com",
  },
  NotBefore: "2024-03-07 00:00:00 +0000 UTC",
  NotAfter:  "2025-03-07 23:59:59 +0000 UTC",
  Error:     "",
  certChain: []*x509.Certificate(nil),
}


```

## todo 备案信息查询 

- 信息收集是网络安全领域的重要步骤，分为被动与主动收集两种方式。
- 被动收集通过搜索引擎、网络空间搜索引擎、Whois查询等公开渠道获取信息，隐蔽性高。
- 主动收集则直接与目标系统交互，如端口扫描、网络映射、DNS枚举等，可能留下痕迹，需谨慎操作。
- 社会工程学、旁站和C段扫描等其他方式也常用于信息收集。
这些方式共同构成了网络安全中不可或缺的信息收集体系。