package saltpack

import (
	"io"

	"github.com/keybase/saltpack"
)

func SaltpackEncrypt(source io.Reader, sink io.WriteCloser, pk publicKey) error {
	// always use the current version of saltpack
	saltpackVersion := saltpack.CurrentVersion()

	receiverBoxKeys := []saltpack.BoxPublicKey{boxPublicKey(pk)}

	var plainsink io.WriteCloser
	var err error

	plainsink, err = saltpack.NewEncryptStream(saltpackVersion, sink, nil, receiverBoxKeys)

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
