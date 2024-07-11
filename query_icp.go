package whox

import (
	"fmt"
	"github.com/fghwett/icp/abbreviateinfo"
)

func queryIcp(domain string) {
	icp := &abbreviateinfo.Icp{}

	domainInfo, err := icp.Query(domain)
	if err == abbreviateinfo.IcpNotForRecord {
		fmt.Printf("%s尚未备案\n", domain)
	} else if err != nil {
		fmt.Printf("%s查询备案信息出错：%v\n", domain, err)
	} else {
		fmt.Printf("域名：%s\n备案号：%s\n备案名称：%s\n备案类型：%s备案\n备案人/单位：%s\n是否被限制访问：%s\n", domain, domainInfo.ServiceLicence, domainInfo.ServiceName, domainInfo.NatureName, domainInfo.UnitName, domainInfo.LimitAccess)
	}
}
