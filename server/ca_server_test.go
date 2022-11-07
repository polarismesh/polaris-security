package server

import (
	_ "embed"
	"os"
	"testing"

	"github.com/polarismesh/polaris-security/util"
)

func TestSelfSignedServiceCertificate(t *testing.T) {
	caCertificate, err := util.ParseCaCertFromFile("test_data/ca-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	caPrivateKey, err := util.ParseCaPrivateKeyFromFile("test_data/ca-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	caServer := &CaServer{
		CaPrivateKey:   caPrivateKey,
		CaCertificate:  caCertificate,
		CertChainBytes: certChainPemBytes,
		RootCertBytes:  rootPemBytes,
	}
	args := &CaBootstrapArgs{
		DNSNames: "polaris-security",
	}
	if err != nil {
		t.Fatalf("build ca server failed:%s", err.Error())
	}
	err = caServer.CreateServicePrivKeyAndCertChain(args)
	if err != nil {
		t.Fatalf("create self-signed key and cert failed:%s", err.Error())
	}

	serviceCertPemBytes, err := os.ReadFile(ServiceCertFileName)
	if err != nil {
		t.Fatal(err)
	}
	serviceCertChainPemBytes, err := os.ReadFile(ServiceCertChainFileName)
	if err != nil {
		t.Fatal(err)
	}
	err = util.SignedCertCanBeVerified(rootPemBytes, serviceCertChainPemBytes, serviceCertPemBytes)
	if err != nil {
		t.Fatal(err)
	}
}
