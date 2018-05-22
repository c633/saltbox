package util

func Zero(in []byte) {
	for i := range in {
		in[i] ^= in[i]
	}
}
