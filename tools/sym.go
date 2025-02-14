// Manual AES encryption and decryption using CBC mode with PKCS7 padding
package scratch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
)

func Aesing() {
	// 16 byte buffer for our key
	k := make([]byte, 16)
	// fill buffer with random data
	rand.Read(k)
	fmt.Printf("k:  %x\n", k)

	// create a cipher using our key
	blk, err := aes.NewCipher(k)
	if err != nil {
		log.Fatal(err)
	}

	// ditto key but for the IV (also length 16)
	iv := make([]byte, blk.BlockSize())
	rand.Read(iv)
	fmt.Printf("iv: %x\n", iv)

	// create our CBC encryptor and decyptor
	enc := cipher.NewCBCEncrypter(blk, iv)
	dec := cipher.NewCBCDecrypter(blk, iv)

	// plaintext
	p := []byte{0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5}
	// ciphertext (same size as plaintext + padding)
	c := make([]byte, len(p))

	// encrypt!
	enc.CryptBlocks(c, p)

	fmt.Printf("p:  %x\n", p)
	fmt.Printf("c:  %x\n", c)

	// zero the plaintext to check decryption works
	for i := range p {
		p[i] = 0
	}

	// decrypt!
	dec.CryptBlocks(p, c)
	fmt.Printf("p:  %x\n", p)
}