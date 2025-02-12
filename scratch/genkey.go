// util/genkey.go
package scratch

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

func printBytes(pub []byte) {
	fmt.Printf("\tpub := []byte{")
	for i := range pub {
		if i > 0 {
			fmt.Printf(",")
		}

		if i%8 == 0 {
			fmt.Printf("\n\t\t")
		}

		fmt.Printf(" 0x%02x", pub[i])
	}
	fmt.Println(" }")
}

func GenerateKey() {
	_, errPub := os.Stat("key.pub")
	_, errPrv := os.Stat("key.prv")

	if errPub == nil && errPrv == nil {
		pub, err := os.ReadFile("key.pub")
		if err != nil {
			log.Fatal(err)
		}
		printBytes(pub)
		log.Fatal("keypair exists, will not overwrite")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	pub := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	err = os.WriteFile("key.pub", pub, 0644)
	if err != nil {
		log.Fatal(err)
	}

	prv := x509.MarshalPKCS1PrivateKey(privateKey)
	err = os.WriteFile("key.prv", prv, 0644)
	if err != nil {
		log.Fatal(err)
	}

	printBytes(pub)
}
