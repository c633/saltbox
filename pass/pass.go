package pass

import (
	"crypto/rand"
	"os"

	"github.com/c633/saltbox/saltpack"
	"github.com/c633/saltbox/util"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	SaltSize = 32
)

func ReadPass() ([]byte, error) {
	state, err := terminal.MakeRaw(0)
	if err != nil {
		return nil, err
	}
	defer terminal.Restore(0, state)
	term := terminal.NewTerminal(os.Stdout, ">")
	passwordString, err := term.ReadPassword("Password:🔐")
	if err != nil {
		return nil, err
	}
	password := []byte(passwordString)
	return password, nil
}

// Parameters for 2017: https://blog.filippo.io/the-scrypt-parameters/
var scryptParams = struct {
	N int
	r int
	p int
}{1048576, 8, 1}

func DeriveKey(passphrase []byte, salt []byte) (*[saltpack.KeySize]byte, error) {
	rawKey, err := scrypt.Key(passphrase, salt, scryptParams.N, scryptParams.r, scryptParams.p, saltpack.KeySize)
	if err != nil {
		return nil, err
	}

	var key [saltpack.KeySize]byte
	copy(key[:], rawKey)
	util.Zero(rawKey)
	util.Zero(passphrase)

	return &key, nil
}

func MakeRand(n int) ([]byte, error) {
	r := make([]byte, n)
	if _, err := rand.Read(r); err != nil {
		return nil, err
	}
	// Do not directly reveal bytes from rand.Read on the wire
	// See https://trac.torproject.org/projects/tor/ticket/17694
	return digest(r), nil
}

func digest(ms ...[]byte) []byte {
	h := sha3.NewShake128()
	for _, m := range ms {
		h.Write(m)
	}
	ret := make([]byte, 32)
	h.Read(ret)
	return ret
}
