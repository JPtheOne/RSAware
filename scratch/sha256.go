package scratch

import (
	"crypto/sha256"
	"log"
)

func GetChecksum() {
	input := "Let's take the sha256 of these bytes!"
	hash := sha256.Sum256([]byte(input))
	log.Printf("%x\n", hash)
}