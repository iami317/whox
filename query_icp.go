package whox

import (
	"encoding/json"
	"fmt"
	"github.com/fghwett/icp/abbreviateinfo"
	"github.com/iami317/logx"
	"io/ioutil"
	"net/http"
)

type Laf struct {
	Icp `json:"icp"`
}

type Icp struct {
	Subject `json:"subject"`
	Website `json:"website"`
}

type Subject struct {
	Name       string      `json:"name"`
	Nature     string      `json:"nature"`
	License    string      `json:"license"`
	UpdateTime interface{} `json:"updateTime"`
}

type Website struct {
	Domain  string `json:"domain"`
	License string `json:"license"`
}

func queryIcpN(domain string) (res Laf) {
	url := fmt.Sprintf("https://phehmt.laf.run/icp?token=637e79b77fd9b2915dfb7e6c&url=%v&version=2&icp=1", domain)
	response, err := http.Get(url)
	if err != nil {
		logx.Errorf("获取域名(%v)的 icp失败：%v", domain, err)
		return
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	err = json.Unmarshal(body, &res)
	if err != nil {
		logx.Errorf("获取域名(%v)的 icp失败：%v", domain, err)
		return
	}
	return res
}

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
