package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/polarismesh/polaris-security/util"

	"github.com/gin-gonic/gin"
	k8s_auth "k8s.io/api/authentication/v1"
	k8s_meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// self signed service cert parameters
const (
	ServicePrivKeyFileName   string        = "service-key.pem"
	ServiceCertChainFileName string        = "service-cert-chain.pem"
	ServiceCertFileName      string        = "service-cert.pem"
	ServiceCertTTL           time.Duration = time.Hour * 24 * 365 * 10
	ServiceOrganization      string        = "cluster.local"
	ServiceCommonName        string        = "polaris-security"
)

const (
	KubeCSRSigingTimeout = 5 * time.Minute
)

type CaBootstrapArgs struct {
	CaPrivateKeyPath string
	CaCertPath       string
	RootCertPath     string
	CertChainPath    string
	Bind             string
	Port             int
	DefaultCertTTL   int32
	DNSNames         string
	Signer           string
}

type SignCertificateRequest struct {
	CSR string `json:"csr"`
	TTL int32  `json:"ttl"`
}

type SignCertificateResponse struct {
	CertChain string `json:"cert_chain"`
	RootCert  string `json:"root_cert"`
	// if signing failed , error message will be wrapped in `Message`
	Message string `json:"msg"`
}

type CaServer struct {
	CaPrivateKey   crypto.PrivateKey
	CaCertificate  *x509.Certificate
	CertChainBytes []byte
	RootCertBytes  []byte
	KubeClientSet  *kubernetes.Clientset
	DefaultCertTTL int32
	Signer         Signer
}

type SignOptions struct {
	CaCertificate  *x509.Certificate
	CaPrivateKey   crypto.PrivateKey
	DefaultCertTTL int32
}

func SignerExists(signer string) bool {
	// TODO
	return true
}

// BuildCaServer create a ca server according to `args`
func BuildCaServer(args *CaBootstrapArgs) (caServer *CaServer, err error) {
	caServer = &CaServer{
		DefaultCertTTL: args.DefaultCertTTL,
	}

	// read pem bytes
	caServer.CertChainBytes, err = os.ReadFile(args.CertChainPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate chain failed: %w", err)
	}
	caServer.RootCertBytes, err = os.ReadFile(args.RootCertPath)
	if err != nil {
		return nil, fmt.Errorf("read root certificate failed: %w", err)
	}
	caCertBytes, err := os.ReadFile(args.CaCertPath)
	if err != nil {
		return nil, err
	}

	// validate ca cert
	err = util.SignedCertCanBeVerified(caServer.RootCertBytes, caServer.CertChainBytes, caCertBytes)
	if err != nil {
		return nil, fmt.Errorf("verify ca cert failed: %w", err)
	}

	// parse key & cert
	caServer.CaPrivateKey, err = util.ParseCaPrivateKeyFromFile(args.CaPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("parse ca private key failed: %w", err)
	}
	caServer.CaCertificate, err = util.ParseCertFromPemBytes(caCertBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca certificate failed: %w", err)
	}

	// create kube config
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", os.Getenv(clientcmd.RecommendedConfigPathEnvVar))
	if err != nil {
		return nil, fmt.Errorf("create kubeclient config failed: %w", err)
	}

	// creates the clientset
	caServer.KubeClientSet, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("create ca server's kube client set failed: %w", err)
	}
	return caServer, nil
}

func (caServer *CaServer) BuildSigner(signerName string) error {
	var signer Signer
	if signerName == "" {
		signer = &PolarisSecuritySigner{}
	} else if SignerExists(signerName) {
		signer = &KubernetesCSRSigner{
			SignerName: signerName,
		}
	} else {
		return fmt.Errorf("bad signer: %s", signerName)
	}
	caServer.Signer = signer
	return nil
}

// CreateServicePrivKeyAndCertChain create self-signed service privkey & cert as a proof of ca server's identity
// in tls connection with the client.
func (caServer *CaServer) CreateServicePrivKeyAndCertChain(args *CaBootstrapArgs) error {
	rsaKey, err := util.GenerateRSAKey(2048, ServicePrivKeyFileName)
	if err != nil {
		return err
	}

	serialNum, err := util.GenerateSerialNum()
	if err != nil {
		return err
	}

	dnsNames := strings.Split(args.DNSNames, ",")
	for i, name := range dnsNames {
		dnsNames[i] = strings.TrimSpace(name)
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			Organization: []string{ServiceOrganization},
			CommonName:   ServiceCommonName,
		},
		// try to compensate for clock skew/network delay
		NotBefore:   time.Now().Add(-10 * time.Second),
		NotAfter:    time.Now().Add(ServiceCertTTL),
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true,
		DNSNames:    dnsNames,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, caServer.CaCertificate, &rsaKey.PublicKey, caServer.CaPrivateKey)
	if err != nil {
		return err
	}
	// encode certificate to PEM format
	certChainPemBytes, err := util.EncodeDataToPemFormat(certBytes, util.CertificateType)
	if err != nil {
		return err
	}

	// write to cert file
	certFile, err := os.Create(ServiceCertFileName)
	if err != nil {
		return err
	}
	defer certFile.Close()
	_, err = certFile.Write(certChainPemBytes)
	if err != nil {
		return err
	}

	// construct cert chain
	certChainPemBytes = append(certChainPemBytes, caServer.CertChainBytes...)

	// write to cert chain file
	certChainFile, err := os.Create(ServiceCertChainFileName)
	if err != nil {
		return err
	}
	defer certChainFile.Close()
	_, err = certChainFile.Write(certChainPemBytes)
	if err != nil {
		return err
	}
	return nil
}

// validateWorkloadIdentity call k8s api-server to verify client's identity.
func validateWorkloadIdentity(kubeClientSet *kubernetes.Clientset, c *gin.Context) error {
	AuthToken := c.GetHeader(util.AuthHeader)
	if AuthToken == "" {
		return fmt.Errorf("jwt token extraction failed: no field %s in headers", util.AuthHeader)
	}
	jwtToken := util.ExtractJwtToken(AuthToken)
	tokenReview := &k8s_auth.TokenReview{
		Spec: k8s_auth.TokenReviewSpec{
			Token: jwtToken,
		},
	}
	result, err := kubeClientSet.AuthenticationV1().TokenReviews().Create(context.TODO(), tokenReview, k8s_meta.CreateOptions{})
	if err != nil {
		return fmt.Errorf("send token review to k8s api server failed: %w", err)
	}
	if result.Status.Error != "" {
		return fmt.Errorf("jwt authentication failed: %s", result.Status.Error)
	}
	if !result.Status.Authenticated {
		return fmt.Errorf("jwt authentication failed: the token is not authenticated")
	}
	return nil
}

// HandleSignCertificateRequest is ca server's main request handler function
func (caServer *CaServer) HandleSignCertificateRequest(c *gin.Context) {
	var request SignCertificateRequest
	err := c.BindJSON(&request)
	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, SignCertificateResponse{
			CertChain: "",
			RootCert:  "",
			Message:   fmt.Sprintf("parse request failed: %s", err.Error()),
		})
		return
	}
	err = validateWorkloadIdentity(caServer.KubeClientSet, c)
	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, SignCertificateResponse{
			CertChain: "",
			RootCert:  "",
			Message:   fmt.Sprintf("jwt identity validation failed: %s", err.Error()),
		})
		return
	}
	certChain, err := caServer.Signer.SignCertificate(caServer.KubeClientSet, &request, &SignOptions{
		DefaultCertTTL: caServer.DefaultCertTTL,
		CaCertificate:  caServer.CaCertificate,
		CaPrivateKey:   caServer.CaPrivateKey,
	})
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, SignCertificateResponse{
			CertChain: "",
			RootCert:  "",
			Message:   fmt.Sprintf("sign certificate failed: %s", err.Error()),
		})
		return
	}
	// chain certificates together
	certChain = append(certChain, caServer.CertChainBytes...)
	// this may cause duplicate root certs, but it doesn't matter
	certChain = append(certChain, caServer.RootCertBytes...)
	c.IndentedJSON(http.StatusOK, SignCertificateResponse{
		CertChain: string(certChain),
		RootCert:  string(caServer.RootCertBytes),
		Message:   "OK",
	})
}
