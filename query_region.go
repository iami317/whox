package whox

import (
	"fmt"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"strconv"
	"strings"
)

// 根据ip地址获取地理位置信息
func queryRegion(ip string) (regionStr string) {
	searcher, err := xdb.NewWithFileOnly("./ip2region.xdb")
	if err != nil {
		return
	}
	defer searcher.Close()
	region, err := searcher.SearchByStr(ip)
	if err != nil {
		fmt.Printf("failed to SearchIP(%s): %s\n", ip, err)
		return
	}
	if strings.Contains(region, "|") {
		regions := strings.Split(region, "|")
		for _, s := range regions {
			_, err := strconv.ParseFloat(s, 64)
			if err != nil {
				regionStr += s + " "
			}
		}
	}
	return
}
