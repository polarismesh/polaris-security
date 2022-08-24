package cmd

import (
	"log"

	"github.com/polarismesh/polaris-security/bootstrap"
	"github.com/polarismesh/polaris-security/server"
	"github.com/spf13/cobra"
)

var (
	serverArgs *server.CaBootstrapArgs
	rootCmd    = &cobra.Command{
		Use:   "polaris-security",
		Short: "polaris-security",
		Long:  "polaris-security",
		Run: func(c *cobra.Command, args []string) {
			bootstrap.Start(serverArgs)
		},
	}
)

func init() {
	serverArgs = &server.CaBootstrapArgs{}
	rootCmd.PersistentFlags().StringVarP(
		&serverArgs.CaPrivateKeyPath, "ca_private_key_path", "", "certs/ca-key.pem", "ca private key file path")
	rootCmd.PersistentFlags().StringVarP(
		&serverArgs.CaCertPath, "ca_cert_path", "", "certs/ca-cert.pem", "ca cert file path")
	rootCmd.PersistentFlags().StringVarP(
		&serverArgs.RootCertPath, "root_cert_path", "", "certs/root-cert.pem", "root cert file path")
	rootCmd.PersistentFlags().StringVarP(
		&serverArgs.CertChainPath, "cert_chain_path", "", "certs/cert-chain.pem", "cert chain file path")
	rootCmd.PersistentFlags().StringVarP(
		&serverArgs.Bind, "bind", "", "0.0.0.0", "ip address to bind")
	rootCmd.PersistentFlags().IntVarP(
		&serverArgs.Port, "port", "", 8888, "port to bind")
	// default cert ttl = 24 hours
	rootCmd.PersistentFlags().Int64VarP(
		&serverArgs.DefaultCertTTL, "default_cert_ttl", "", 3600, "default cert ttl (in seconds)")
	// DNSNames used as SAN in ca self-signed service certificate
	rootCmd.PersistentFlags().StringVarP(
		&serverArgs.DNSNames, "dns_names", "", "polaris-security", `dns names used as SAN in ca self-signed service certificate,
		a ',' delimited string, example: polaris-security,polaris-svc`)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
