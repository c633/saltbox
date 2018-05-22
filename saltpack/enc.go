package saltpack

import (
	"io"

	"github.com/keybase/saltpack"
)

func SaltpackEncrypt(source io.Reader, sink io.WriteCloser, keypair boxKeyPair) error {
	// always use the current version of saltpack
	saltpackVersion := saltpack.CurrentVersion()

	senderBoxKey := boxSecretKey(keypair)
	receiverBoxKeys := []saltpack.BoxPublicKey{boxPublicKey(keypair.Public)}

	var plainsink io.WriteCloser
	var err error

	plainsink, err = saltpack.NewEncryptStream(saltpackVersion, sink, senderBoxKey, receiverBoxKeys)

	if err != nil {
		return err
	}

	_, err = io.Copy(plainsink, source)
	if err != nil {
		return err
	}

	if err := plainsink.Close(); err != nil {
		return err
	}
	return sink.Close()
}
