# saltbox

Password-based [NaCl](https://nacl.cr.yp.to/) and [saltpack](https://saltpack.org/) for file encryption. __Use at your own risk__.

### Installation

```
go get github.com/c633/saltbox/...
```

### Usage

```
# to encrypt
saltbox encrypt -i inputfile [-p passphrase] [-o output]
# to decrypt
saltbox decrypt -i inputfile [-p passphrase] [-o output]
```
