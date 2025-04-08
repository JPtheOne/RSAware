package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	println("🔐 Starting HTTPS server...")
	http.HandleFunc("/upload", uploadHandler)

	host := getEnv("SERVER_HOST", "localhost")
	port := getEnv("SERVER_PORT", "8443")
	addr := fmt.Sprintf("%s:%s", host, port)

	certPath := "cert.pem"
	keyPath := "key.pem"

	// Create certificates if not existent
	os.MkdirAll("certs", 0755)
	if err := ensureCert(certPath, keyPath); err != nil {
		log.Fatal("❌ Error generating cert:", err)
	}

	fmt.Printf("🚀 HTTPS Server Active in https://%s/upload\n", addr)

	server := &http.Server{
		Addr:      addr,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20) // 10MB máximo
	if err != nil {
		http.Error(w, "Error parsing form: "+err.Error(), http.StatusBadRequest)
		return
	}

	timestamp := time.Now().Format("20060102-150405")
	destDir := filepath.Join("Obtained Files", timestamp)
	os.MkdirAll(destDir, 0755)

	for _, field := range []string{"file.keys", "master.key"} {
		file, header, err := r.FormFile(field)
		if err != nil {
			http.Error(w, "Error receiving "+field+": "+err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()

		dstPath := filepath.Join(destDir, header.Filename)
		dstFile, err := os.Create(dstPath)
		if err != nil {
			http.Error(w, "Error creating file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer dstFile.Close()

		_, err = io.Copy(dstFile, file)
		if err != nil {
			http.Error(w, "Error copying file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Println("✅ Saved:", dstPath)
	}

	fmt.Fprintln(w, "Files received correctly.")
}

func ensureCert(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	fmt.Println("🔐 Self-signed cert generated.")
	return nil
}

func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}
