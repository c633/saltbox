package cmd

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/c633/saltbox/pass"
	"github.com/c633/saltbox/saltpack"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringP("input", "i", "", "specify an input file (required)")
	decryptCmd.Flags().StringP("passphrase", "p", "", "specify the passphrase for the decryption")
	decryptCmd.Flags().StringP("output", "o", ".", "specify the output directory (input file's directory by default)")
	decryptCmd.MarkFlagRequired("input")
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file encrypted with saltbox",
	Long:  "Decrypt a file encrypted with saltbox",
	Run:   decrypt,
}

func decrypt(cmd *cobra.Command, args []string) {
	var err error

	input := cmd.Flag("input").Value.String()
	output := cmd.Flag("output").Value.String()
	if cmd.Flag("output").Changed {
		orgName := strings.TrimSuffix(input, filepath.Ext(input))
		output = filepath.Join(output, filepath.Base(orgName))
		fmt.Println(output)
	} else {
		output = strings.TrimSuffix(input, filepath.Ext(input))
	}

	var source io.Reader
	if source, err = os.Open(input); err != nil {
		log.Fatal(err)
	}

	salt := make([]byte, pass.SaltSize)
	if n, err := source.Read(salt); n != pass.SaltSize || err != nil {
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

	var sink io.WriteCloser
	if sink, err = os.Create(output); err != nil {
		log.Fatal(err)
	}

	if err = saltpack.SaltpackDecrypt(source, sink, keypair); err != nil {
		log.Fatal(err)
	}
}
