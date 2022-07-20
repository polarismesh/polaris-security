package util

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
)

type BlockType string

const (
	RSAPrivateKeyType          = "RSA Private Key"
	PrivateKeyType             = "PRIVATE KEY"
	CertificateSignRequestType = "CERTIFICATE REQUEST"
	CertificateType            = "CERTIFICATE"
)

const (
	AuthHeader   = "Authorization"
	BearerPrefix = "Bearer "
)

// GenerateRSAKey generates an RSA keypair of the given `bits` size.
// if `saveFilePath` is not empty, then generated keypair will be saved in x509 PEM format.
func GenerateRSAKey(bits int, saveFilePath string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("rsa generate key failed: %w", err)
	}
	if saveFilePath != "" {
		x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyFile, err := os.Create(saveFilePath)
		if err != nil {
			return nil, fmt.Errorf("create private key file failed: %w", err)
		}
		defer privateKeyFile.Close()
		privateBlock := pem.Block{Type: PrivateKeyType, Bytes: x509PrivateKey}
		err = pem.Encode(privateKeyFile, &privateBlock)
		if err != nil {
			return nil, fmt.Errorf("encode pem format content to private key file failed: %w", err)
		}
	}
	return privateKey, nil
}

// SignedCertCanBeVerified checks whether `signedCertPemBytes` can be successfully verified by `rootPemBytes` and `certChainPemBytes`.
func SignedCertCanBeVerified(rootPemBytes []byte, certChainPemBytes []byte, signedCertPemBytes []byte) error {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPemBytes)
	if !ok {
		return fmt.Errorf("failed to parse root certificate")
	}
	intermediates := x509.NewCertPool()
	ok = intermediates.AppendCertsFromPEM(certChainPemBytes)
	if !ok {
		return fmt.Errorf("failed to parse cert chain")
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}
	cert, err := ParseCertFromPemBytes(signedCertPemBytes)
	if err != nil {
		return fmt.Errorf("parse signed cert failed: %w", err)
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: %w", err)
	}
	return nil
}

// GenerateSerialNum generates a random big.Int to be used as a serial number in certificate.
func GenerateSerialNum() (*big.Int, error) {
	// big random int to use as serial number
	serialNumLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNum, err := rand.Int(rand.Reader, serialNumLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number failed : %w", err)
	}
	return serialNum, nil
}

// ParseCaPrivateKeyFromFile parse a PEM-encoded ca private key from file `caPrivateKeyPath`
func ParseCaPrivateKeyFromFile(caPrivateKeyPath string) (privKey crypto.PrivateKey, err error) {
	caPrivateKeyBytes, err := os.ReadFile(caPrivateKeyPath)
	if err != nil {
		return nil, err
	}
	block, err := DecodePemData(caPrivateKeyBytes, PrivateKeyType)
	if err != nil {
		return nil, err
	}
	privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

// ParseCaCertFromFile parse a PEM-encoded ca cert-chain from file `caCertPath`
func ParseCaCertFromFile(caCertPath string) (caCert *x509.Certificate, err error) {
	caCertPemBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	caCert, err = ParseCertFromPemBytes(caCertPemBytes)
	return
}

// ParseCertFromPemBytes parse x509 format cert from `certPemBytes`
func ParseCertFromPemBytes(certPemBytes []byte) (*x509.Certificate, error) {
	block, err := DecodePemData(certPemBytes, CertificateType)
	if err != nil {
		return nil, fmt.Errorf("decode pem encoded cert bytes failed: %w", err)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert from block bytes failed: %w", err)
	}
	return cert, nil
}

// ParseCsrFromPemBytes parse x509 format certificate sign request from `csrPemBytes`
func ParseCsrFromPemBytes(csrPemBytes []byte) (*x509.CertificateRequest, error) {
	block, err := DecodePemData(csrPemBytes, CertificateSignRequestType)
	if err != nil {
		return nil, fmt.Errorf("decode pem encoded CSR bytes failed: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR from block bytes failed: %w", err)
	}
	return csr, nil
}

// ExtractJwtToken extract jwt-token from the `fullToken`
func ExtractJwtToken(fullToken string) (jwtToken string) {
	bearerPrefixLen := len(BearerPrefix)
	// strip the bearer prefix if it exists
	if len(fullToken) >= bearerPrefixLen && strings.EqualFold(fullToken[:bearerPrefixLen], BearerPrefix) {
		return fullToken[bearerPrefixLen:]
	}
	return fullToken
}

// DecodePemData decodes `pemData` into `blockType` pem block
func DecodePemData(pemData []byte, blockType BlockType) (block *pem.Block, err error) {
	block, _ = pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	} else if block.Type != string(blockType) {
		return nil, fmt.Errorf("wrong PEM block type, expect: %v, actual: %v", blockType, block.Type)
	}
	return block, nil
}

// EncodeDataToPemFormat encode `dataBytes` into `blockType` in-memory pem bytes
func EncodeDataToPemFormat(dataBytes []byte, blockType BlockType) (pemBytes []byte, err error) {
	block := &pem.Block{
		Type:  string(blockType),
		Bytes: dataBytes,
	}

	pemBytes = pem.EncodeToMemory(block)
	if pemBytes == nil {
		err = fmt.Errorf("pem.EncodeToMemory Failed: invalid headers")
	}
	return
}
