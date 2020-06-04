package certs

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/micro/cli/v2"
	"github.com/micro/go-micro/v2/util/pki"
)

// Commands returns certs' commands
func Commands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "certs",
			Usage: "Generate certificates for the micro platform",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "out_dir",
					Usage: "Output Directory",
					Value: filepath.Join(os.TempDir(), "certs"),
				},
			},
			Subcommands: []*cli.Command{
				{
					Name:  "generate",
					Usage: "Generate certs",
					Flags: []cli.Flag{
						&cli.StringSliceFlag{
							Name:  "services",
							Usage: "list of services to generate certificates for",
							Value: cli.NewStringSlice("go.micro", "go.micro.api"),
						},
					},
					Action: generate,
				},
			},
		},
	}
}

func generate(c *cli.Context) error {
	if err := os.MkdirAll(c.String("out_dir"), 0700); err != nil {
		return err
	}
	// Generate CA
	fmt.Println("Generating CA")
	pub, priv, err := pki.GenerateKey()
	if err != nil {
		return err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	ca, key, err := pki.CA(
		pki.KeyPair(pub, priv),
		pki.IsCA(),
		pki.Subject(pkix.Name{CommonName: "micro-platform", Organization: []string{"Micro"}}),
		pki.SerialNumber(serialNumber),
		pki.DNSNames("localhost"),
		pki.IPAddresses(net.ParseIP("127.0.0.1")),
		pki.NotBefore(time.Now()),
		pki.NotAfter(time.Now().Add(100*time.Hour*8760)),
	)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(c.String("out_dir"), "ca.pem"), ca, 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(c.String("out_dir"), "key.pem"), key, 0600); err != nil {
		return err
	}

	for _, s := range c.StringSlice("services") {
		fmt.Println("Generating certificate for", s)
		outDir := filepath.Join(c.String("out_dir"), strings.ReplaceAll(s, ".", "-"))
		if err := os.MkdirAll(outDir, 0700); err != nil {
			return err
		}
		if err := ioutil.WriteFile(filepath.Join(outDir, "ca.pem"), ca, 0600); err != nil {
			return err
		}
		pub, priv, err := pki.GenerateKey()
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(filepath.Join(outDir, "key.pem"), priv, 0600); err != nil {
			return err
		}
		csr, err := pki.CSR(
			pki.KeyPair(pub, priv),
			pki.Subject(
				pkix.Name{
					CommonName:         strings.ReplaceAll(s, ".", "-"),
					Organization:       []string{"Micro"},
					OrganizationalUnit: []string{"micro-platform"},
				},
			),
		)
		if err != nil {
			return err
		}
		serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return err
		}
		if err != nil {
			return err
		}
		cert, err := pki.Sign(
			ca,
			key,
			csr,
			pki.SerialNumber(serialNumber),
			pki.NotBefore(time.Now()),
			pki.NotAfter(time.Now().Add(100*time.Hour*8760)),
		)
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(filepath.Join(outDir, "cert.pem"), cert, 0600); err != nil {
			return err
		}
	}
	fmt.Println("Certificates written to", c.String("out_dir"))
	return nil
}
