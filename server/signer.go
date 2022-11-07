package server

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/polarismesh/polaris-security/util"
	k8s_cert "k8s.io/api/certificates/v1"
	k8s_meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	k8s_csr "k8s.io/client-go/util/certificate/csr"
)

type Signer interface {
	SignCertificate(kubeClientSet *kubernetes.Clientset, request *SignCertificateRequest, opts *SignOptions) (signedCertPemBytes []byte, err error)
}

// polaris-security sign the csr by itself as an intermediate ca
type PolarisSecuritySigner struct{}

// polaris-security trasform the csr to Kubernetes CSR and send to real signer
type KubernetesCSRSigner struct {
	SignerName string
}

func (signer *PolarisSecuritySigner) SignCertificate(kubeClientSet *kubernetes.Clientset, request *SignCertificateRequest, opts *SignOptions) (signedCertPemBytes []byte, err error) {
	// decode csr from PEM encoded bytes
	csr, err := util.ParseCsrFromPemBytes([]byte(request.CSR))
	if err != nil {
		return nil, err
	}

	ttl := request.TTL
	// use the default cert ttl if the provided value is invalid
	if ttl <= 0 {
		ttl = opts.DefaultCertTTL
	}

	serialNum, err := util.GenerateSerialNum()
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNum,
		Subject:      csr.Subject,
		// try to compensate for clock skew/network delay
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().Add(time.Duration(ttl) * time.Second),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IsCA:           false,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		URIs:           csr.URIs,
		EmailAddresses: csr.EmailAddresses,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, opts.CaCertificate, csr.PublicKey, opts.CaPrivateKey)
	if err != nil {
		return nil, err
	}

	// encode certificate to PEM format
	signedCertPemBytes, err = util.EncodeDataToPemFormat(certBytes, util.CertificateType)
	return
}

func (signer *KubernetesCSRSigner) SignCertificate(kubeClientSet *kubernetes.Clientset, request *SignCertificateRequest, opts *SignOptions) (signedCertPemBytes []byte, err error) {
	ttl := request.TTL
	// use the default cert ttl if the provided value is invalid
	if ttl <= 0 {
		ttl = opts.DefaultCertTTL
	}
	csr := &k8s_cert.CertificateSigningRequest{
		TypeMeta: k8s_meta.TypeMeta{Kind: "CertificateSigningRequest"},
		Spec: k8s_cert.CertificateSigningRequestSpec{
			Groups:            []string{"system:authenticated"},
			Request:           []byte(request.CSR),
			Usages:            []k8s_cert.KeyUsage{k8s_cert.UsageClientAuth},
			SignerName:        signer.SignerName,
			ExpirationSeconds: &ttl,
		},
	}
	csr.GenerateName = "csr-"

	// create kubernetes CSR
	req, err := kubeClientSet.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), csr, k8s_meta.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create kubernetes CSR failed :%w", err)
	}

	// approve the CSR manually
	_, err = kubeClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), req.Name, req, k8s_meta.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("error update csr approval:%s for the reason:%w", csr.Name, err)
	}

	// wait for signing
	ctx, cancel := context.WithTimeout(context.Background(), KubeCSRSigingTimeout)
	defer cancel()

	// wait for the certificate to be signed.
	crtPEM, err := k8s_csr.WaitForCertificate(ctx, kubeClientSet, req.Name, req.UID)
	if err != nil {
		return nil, fmt.Errorf("wait for certificate failed :%w", err)
	}
	return crtPEM, nil
}
