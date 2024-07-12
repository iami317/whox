package main

import (
	"github.com/iami317/whox"
	"github.com/k0kubun/pp/v3"
)

func main() {
	domain, asnInfo, cert := whox.Run("github.com")
	pp.Println(domain)
	pp.Println(asnInfo)
	pp.Println(cert)
}
