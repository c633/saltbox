package cmd

import (
	"io"
	"os"
	"path/filepath"

	"github.com/awnumar/memguard"

	"github.com/c633/saltbox/pass"
	"github.com/c633/saltbox/saltpack"
	"github.com/c633/saltbox/util"
	"github.com/spf13/cobra"
)

const (
	ext = ".enc"
)

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringP("input", "i", "", "specify an input file (required)")
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
	defer memguard.DestroyAll()

	var err error

	salt, err := pass.MakeRand(pass.SaltSize)
	if err != nil {
		util.Fatal(err)
	}
	passphrase, err := pass.ReadPass()
	if err != nil {
		util.Fatal(err)
	}
	keyStream, err := pass.DeriveKey(passphrase, salt)
	if err != nil {
		util.Fatal(err)
	}
	keypair, err := saltpack.MakeBoxKeyPairFromSecret(keyStream)
	defer memguard.WipeBytes(keypair.Secret[:])
	if err != nil {
		util.Fatal(err)
	}

	input := cmd.Flag("input").Value.String()

	var source io.Reader
	if source, err = os.Open(input); err != nil {
		util.Fatal(err)
	}

	output := cmd.Flag("output").Value.String()
	if cmd.Flag("output").Changed {
		output = filepath.Join(output, filepath.Base(input)+ext)
	} else {
		output = input + ext
	}

	var sink io.WriteCloser
	if sink, err = os.Create(output); err != nil {
		util.Fatal(err)
	}
	n, err := sink.Write(salt)
	if n != pass.SaltSize || err != nil {
		util.Fatal(err)
	}

	if err = saltpack.SaltpackEncrypt(source, sink, keypair); err != nil {
		util.Fatal(err)
	}
}
