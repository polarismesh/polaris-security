package server

import (
	_ "embed"
	"os"
	"testing"

	"github.com/polarismesh/polaris-security/util"
)

//go:embed test_data/test_csr.csr
var csrBytes []byte

//go:embed test_data/root-cert.pem
var rootPemBytes []byte

//go:embed test_data/cert-chain.pem
var certChainPemBytes []byte

func TestCreateCertificate(t *testing.T) {
	caPrivateKey, err := util.ParseCaPrivateKeyFromFile("test_data/ca-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := util.ParseCaCertFromFile("test_data/ca-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	badCsrBytes, err := util.EncodeDataToPemFormat([]byte("abcd"), util.CertificateSignRequestType)
	if err != nil {
		t.Fatal(err)
	}

	testCases := map[string]struct {
		request           *SignCertificateRequest
		shouldReturnError bool
	}{
		"Success": {
			request: &SignCertificateRequest{
				TTL: 10000000,
				CSR: string(csrBytes),
			},
			shouldReturnError: false,
		},
		"CSR non-pem format": {
			request: &SignCertificateRequest{
				TTL: 10000000,
				CSR: string("abc"),
			},
			shouldReturnError: true,
		},
		"Bad CSR": {
			request: &SignCertificateRequest{
				TTL: 10000000,
				CSR: string(badCsrBytes),
			},
			shouldReturnError: true,
		},
		"Negative TTL": {
			request: &SignCertificateRequest{
				TTL: -10000000,
				CSR: string(csrBytes),
			},
			shouldReturnError: false,
		},
	}
	for id, c := range testCases {
		signedCertPemBytes, err := SignCertificate(c.request, &SignOptions{
			DefaultCertTTL: 3600,
			CaCertificate:  caCertificate,
			CaPrivateKey:   caPrivateKey,
		})
		if c.shouldReturnError && err == nil {
			t.Errorf("Case %s: expecting an error,  but got none", id)
		} else if !c.shouldReturnError && err != nil {
			t.Errorf("Case %s: expecting SignCertificate success,  but got error %s", id, err.Error())
		} else if !c.shouldReturnError {
			err = util.SignedCertCanBeVerified(rootPemBytes, certChainPemBytes, signedCertPemBytes)
			if err != nil {
				t.Errorf("Case %s: signed cert verification failed: %s", id, err.Error())
			}
		}
	}
}

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
