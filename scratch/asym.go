package scratch

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"log"
	"fmt"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.PublicKey

	p := []byte{0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5}
	fmt.Printf("Plaintext:\t%v\n", p)

	c, err := rsa.EncryptOAEP(
		sha256.New(), rand.Reader, &publicKey, p, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ciphertext:\t%v\n", c)

	pd, err := rsa.DecryptOAEP(
		sha256.New(), rand.Reader, privateKey, c, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted:\t%v\n", pd)
}