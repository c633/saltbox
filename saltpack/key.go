package saltpack

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"github.com/awnumar/memguard"

	"github.com/keybase/saltpack"
	"golang.org/x/crypto/nacl/box"
)

const (
	KeySize   = 32
	nonceSize = 24
)

var DecryptionErr = errors.New("Decryption error")

type publicKey [KeySize]byte
type secretKey [KeySize]byte

type boxKeyPair struct {
	Public publicKey
	Secret *secretKey
}

func MakeBoxKeyPairFromSecret(secret *memguard.LockedBuffer) (boxKeyPair, error) {
	defer secret.Destroy()
	r := bytes.NewReader(secret.Buffer())

	return generateBoxKeyPair(r)
}

func generateBoxKeyPair(reader io.Reader) (boxKeyPair, error) {
	pub, priv, err := box.GenerateKey(reader)
	if err != nil {
		return boxKeyPair{}, err
	}
	return boxKeyPair{
		Public: *pub,
		Secret: (*secretKey)(priv),
	}, nil
}

type boxPublicKey publicKey

var _ saltpack.BoxPublicKey = boxPublicKey{}

func (b boxPublicKey) ToKID() []byte {
	return b[:]
}

func (b boxPublicKey) ToRawBoxKeyPointer() *saltpack.RawBoxKey {
	return (*saltpack.RawBoxKey)(&b)
}

func (b boxPublicKey) CreateEphemeralKey() (saltpack.BoxSecretKey, error) {
	kp, err := generateBoxKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}

	return boxSecretKey(kp), nil
}

func (b boxPublicKey) HideIdentity() bool {
	return false
}

type boxPrecomputedSharedKey [KeySize]byte

var _ saltpack.BoxPrecomputedSharedKey = boxPrecomputedSharedKey{}

func (k boxPrecomputedSharedKey) Unbox(nonce saltpack.Nonce, msg []byte) (
	[]byte, error) {
	ret, ok := box.OpenAfterPrecomputation(
		[]byte{}, msg, (*[nonceSize]byte)(&nonce), (*[KeySize]byte)(&k))
	if !ok {
		return nil, DecryptionErr
	}
	return ret, nil
}

func (k boxPrecomputedSharedKey) Box(nonce saltpack.Nonce, msg []byte) []byte {
	ret := box.SealAfterPrecomputation([]byte{}, msg,
		(*[nonceSize]byte)(&nonce), (*[KeySize]byte)(&k))
	return ret
}

type boxSecretKey boxKeyPair

var _ saltpack.BoxSecretKey = boxSecretKey{}

func (n boxSecretKey) Box(
	receiver saltpack.BoxPublicKey, nonce saltpack.Nonce, msg []byte) []byte {
	ret := box.Seal([]byte{}, msg, (*[nonceSize]byte)(&nonce),
		(*[KeySize]byte)(receiver.ToRawBoxKeyPointer()),
		(*[KeySize]byte)(n.Secret))
	return ret
}

func (n boxSecretKey) Unbox(
	sender saltpack.BoxPublicKey, nonce saltpack.Nonce, msg []byte) (
	[]byte, error) {
	ret, ok := box.Open([]byte{}, msg, (*[nonceSize]byte)(&nonce),
		(*[KeySize]byte)(sender.ToRawBoxKeyPointer()),
		(*[KeySize]byte)(n.Secret))
	if !ok {
		return nil, DecryptionErr
	}
	return ret, nil
}

func (n boxSecretKey) GetPublicKey() saltpack.BoxPublicKey {
	return boxPublicKey(n.Public)
}

func (n boxSecretKey) Precompute(
	sender saltpack.BoxPublicKey) saltpack.BoxPrecomputedSharedKey {
	var res boxPrecomputedSharedKey
	box.Precompute((*[KeySize]byte)(&res),
		(*[KeySize]byte)(sender.ToRawBoxKeyPointer()),
		(*[KeySize]byte)(n.Secret))
	return res
}

type keyring boxSecretKey

var _ saltpack.Keyring = keyring{}

func (n keyring) LookupBoxSecretKey(
	kids [][]byte) (int, saltpack.BoxSecretKey) {
	sk := (boxSecretKey)(n)
	pkKid := sk.GetPublicKey().ToKID()
	for i, kid := range kids {
		if bytes.Equal(pkKid, kid) {
			return i, sk
		}
	}

	return -1, nil
}

func (n keyring) LookupBoxPublicKey(kid []byte) saltpack.BoxPublicKey {
	var pk boxPublicKey
	if len(kid) != len(pk) {
		return nil
	}
	copy(pk[:], kid)
	return pk
}

func (n keyring) GetAllBoxSecretKeys() []saltpack.BoxSecretKey {
	return []saltpack.BoxSecretKey{boxSecretKey(n)}
}

func (n keyring) ImportBoxEphemeralKey(kid []byte) saltpack.BoxPublicKey {
	return n.LookupBoxPublicKey(kid)
}

func (n keyring) CreateEphemeralKey() (saltpack.BoxSecretKey, error) {
	kp, err := generateBoxKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}

	return boxSecretKey(kp), nil
}

func (n keyring) LookupSigningPublicKey(kid []byte) saltpack.SigningPublicKey {
	panic("unimplemented")
}
