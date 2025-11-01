// This program securely generates an Argon2id hash for a given password.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

const (
	memory      = 64 * 1024
	iterations  = 1
	parallelism = 4
	saltLength  = 16
	keyLength   = 32
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: go run main.go <password>")
		os.Exit(1)
	}
	password := os.Args[1]
	if password == "" {
		fmt.Fprintln(os.Stderr, "Error: password cannot be empty.")
		os.Exit(1)
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating salt: %v\n", err)
		os.Exit(1)
	}
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	hashString := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash)
	fmt.Printf("\n---\nGenerated Argon2id Hash:\n%s\n---\n", hashString)
	fmt.Println("Copy the entire hash string and paste it into the 'password' field in your config.yaml.")
}
