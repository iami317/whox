package main

import (
	"fmt"
	"github.com/iami317/whox"
	"github.com/k0kubun/pp/v3"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"time"
)

func main() {
	domain, asnInfo, cert := whox.Run("json.cn")
	pp.Println(domain)
	pp.Println(asnInfo)
	pp.Println(cert)

	if len(domain.DomainIp) > 0 {
		ip2region(domain.DomainIp)
	}

}

// 根据ip地址获取地理位置信息
func ip2region(ip string) {
	searcher, err := xdb.NewWithFileOnly("./ip2region.xdb")
	if err != nil {
		return
	}
	defer searcher.Close()
	var tStart = time.Now()
	region, err := searcher.SearchByStr(ip)
	if err != nil {
		fmt.Printf("failed to SearchIP(%s): %s\n", ip, err)
		return
	}

	fmt.Printf("{region: %s, took: %s}\n", region, time.Since(tStart))
}
