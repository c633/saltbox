package saltpack

import (
	"bufio"
	"io"

	"github.com/keybase/saltpack"
)

func SaltpackDecrypt(source io.Reader, sink io.WriteCloser, secretKey boxKeyPair) error {
	// How much do we need to peek to get at the mode number?
	// How much do we need to peek to get at the mode number?
	// - bin tag (2, 3, or 5 bytes)
	// - array tag (1 byte)
	// - format name (9 bytes, including tag)
	// - version (3 bytes, including tag)
	// - and finally, the mode (1 byte)
	// sums to 16-19 bytes.
	peekable := bufio.NewReader(source)
	_, err := peekable.Peek(19)
	if err != nil {
		return err
	}

	_, plainsource, err := saltpack.NewDecryptStream(saltpack.CheckKnownMajorVersion, peekable, keyring(secretKey))
	if err != nil {
		return err
	}

	_, err = io.Copy(sink, plainsource)
	if err != nil {
		return err
	}

	return sink.Close()
}
