package main

import (
	"github.com/iami317/whox"
	"github.com/k0kubun/pp/v3"
)

func main() {
	domain, asnInfo, cert, icp := whox.Run("json.cn")
	pp.Println(domain)
	pp.Println(asnInfo)
	pp.Println(cert)
	pp.Println(icp)

}
