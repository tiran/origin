package util

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

func CertPoolFromFile(filename string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if len(filename) == 0 {
		return pool, nil
	}

	pemBlock, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	certs, err := CertificatesFromPEM(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("Error reading %s: %s", filename, err)
	}

	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return pool, nil
}

func CertificatesFromFile(file string) ([]*x509.Certificate, error) {
	if len(file) == 0 {
		return nil, nil
	}
	pemBlock, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	certs, err := CertificatesFromPEM(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("Error reading %s: %s", file, err)
	}
	return certs, nil
}

func CertificatesFromPEM(pemCerts []byte) ([]*x509.Certificate, error) {
	ok := false
	certs := []*x509.Certificate{}
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, err
		}

		certs = append(certs, cert)
		ok = true
	}

	if !ok {
		return certs, errors.New("Could not read any certificates")
	}
	return certs, nil
}

// PrivateKeysFromPEM extracts all blocks recognized as private keys into an output PEM encoded byte array,
// or returns an error. If there are no private keys it will return an empty byte buffer.
func PrivateKeysFromPEM(pemCerts []byte) ([]byte, error) {
	buf := &bytes.Buffer{}
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if len(block.Headers) != 0 {
			continue
		}
		switch block.Type {
		// defined in OpenSSL pem.h
		case "RSA PRIVATE KEY", "PRIVATE KEY", "ANY PRIVATE KEY", "DSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY":
			if err := pem.Encode(buf, block); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

// Generate a random password from a cryptographically secure PRNG
func GeneratePassword(pwlen int, charset []byte) (string, error) {
	if pwlen <= 0 {
		return "", errors.New("pwlen must be larger than 0.")
	}
	cslen := len(charset)
	if cslen > 255 || cslen == 0 {
		return "", errors.New("charset is empty or has more than 255 runes.")
	}
	// The mask is used to map each rune to multiple values of each random
	// byte. In case the length of the charset is not a power of 2, some
	// random values must be ignored in order to archive an equal
	// distribution.
	randmask := byte(cslen)
	randmax := byte(256 - (256 % cslen))
	// Read more random bytes to compensate for ignored values. It's cheaper
	// to read a little more data than to perform multiple syscalls.
	randbytes := make([]byte, pwlen+(pwlen/2))
	pw := make([]byte, pwlen)
	i := 0
	for {
		if _, err := io.ReadFull(rand.Reader, randbytes); err != nil {
			return "", err
		}
		for _, b := range randbytes {
			if b >= randmax {
				continue
			}
			pw[i] = charset[b%randmask]
			i++
			if i == pwlen {
				return string(pw), nil
			}
		}
	}
}
