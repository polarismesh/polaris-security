package bootstrap

import (
	"fmt"
	"log"

	"github.com/polarismesh/polaris-security/server"

	"github.com/gin-gonic/gin"
)

const (
	SignCertificateURI = "/security/v1/sign_certificate"
)

// start ca server
func Start(args *server.CaBootstrapArgs) {
	caServer, err := server.BuildCaServer(args)
	if err != nil {
		log.Fatal(err)
	}
	err = caServer.CreateServicePrivKeyAndCertChain(args)
	if err != nil {
		log.Fatal(err)
	}
	addr := fmt.Sprint(args.Bind, ":", args.Port)
	router := gin.Default()
	// register handler function
	router.POST(SignCertificateURI, caServer.HandleSignCertificateRequest)
	err = router.RunTLS(addr, server.ServiceCertChainFileName, server.ServicePrivKeyFileName)
	if err != nil {
		log.Fatal(err)
	}
}
