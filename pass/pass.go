package pass

import (
	"crypto/rand"
	"crypto/subtle"
	"os"

	"github.com/awnumar/memguard"
	"github.com/c633/saltbox/saltpack"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	SaltSize = 32
)

func ReadPass() (*memguard.LockedBuffer, error) {
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
	password, err := memguard.NewMutableFromBytes([]byte(passwordString))
	if err != nil {
		return nil, err
	}
	return password, nil
}

// Parameters for 2017: https://blog.filippo.io/the-scrypt-parameters/
var scryptParams = struct {
	N int
	r int
	p int
}{1048576, 8, 1}

func DeriveKey(passphrase *memguard.LockedBuffer, salt []byte) (*memguard.LockedBuffer, error) {
	defer passphrase.Destroy()

	buf := make([]byte, passphrase.Size())
	defer memguard.WipeBytes(buf)
	subtle.ConstantTimeCopy(1, buf, passphrase.Buffer())

	rawKey, err := scrypt.Key(buf, salt, scryptParams.N, scryptParams.r, scryptParams.p, saltpack.KeySize)
	if err != nil {
		return nil, err
	}

	key, err := memguard.NewImmutableFromBytes(rawKey)
	if err != nil {
		return nil, err
	}
	return key, nil
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
