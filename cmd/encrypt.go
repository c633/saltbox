package cmd

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/c633/saltbox/pass"
	"github.com/c633/saltbox/saltpack"
	"github.com/spf13/cobra"
)

const (
	ext = ".enc"
)

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringP("input", "i", "", "specify an input file (required)")
	encryptCmd.Flags().StringP("passphrase", "p", "", "specify the passphrase for the encryption")
	encryptCmd.Flags().StringP("output", "o", "", "specify the output directory (input file's directory by default)")
	encryptCmd.MarkFlagRequired("input")
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file using saltbox",
	Long:  "Encrypt a file using saltbox",
	Run:   encrypt,
}

func encrypt(cmd *cobra.Command, args []string) {
	var err error

	salt, err := pass.MakeRand(pass.SaltSize)
	if err != nil {
		log.Fatal(err)
	}
	passphrase := []byte(cmd.Flag("passphrase").Value.String())
	if len(passphrase) == 0 {
		if passphrase, err = pass.ReadPass(); err != nil {
			log.Fatal(err)
		}
	}
	keyStream, err := pass.DeriveKey(passphrase, salt)
	if err != nil {
		log.Fatal(err)
	}
	keypair, err := saltpack.MakeBoxKeyPairFromSecret(keyStream)
	if err != nil {
		log.Fatal(err)
	}

	input := cmd.Flag("input").Value.String()

	var source io.Reader
	if source, err = os.Open(input); err != nil {
		log.Fatal(err)
	}

	output := cmd.Flag("output").Value.String()
	if cmd.Flag("output").Changed {
		output = filepath.Join(output, filepath.Base(input)+ext)
	} else {
		output = input + ext
	}

	var sink io.WriteCloser
	if sink, err = os.Create(output); err != nil {
		log.Fatal(err)
	}
	n, err := sink.Write(salt)
	if n != pass.SaltSize || err != nil {
		log.Fatal(err)
	}

	if err = saltpack.SaltpackEncrypt(source, sink, keypair.Public); err != nil {
		log.Fatal(err)
	}
}
