package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

func generatePOMContent(groupId, artifactId, version string) string {
	groupId = strings.ReplaceAll(groupId, "/", ".")
	return fmt.Sprintf(`<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://www.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>%s</groupId>
    <artifactId>%s</artifactId>
    <version>%s</version>
    <packaging>aar</packaging>
</project>`, groupId, artifactId, version)
}

func uploadToGCS(ctx context.Context, client *storage.Client, bucketName, objectName string, file io.Reader) error {
	bucket := client.Bucket(bucketName)
	obj := bucket.Object(objectName)
	w := obj.NewWriter(ctx)
	if _, err := io.Copy(w, file); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return nil
}

func downloadFromGCS(ctx context.Context, client *storage.Client, bucketName, objectName string) ([]byte, error) {
	bucket := client.Bucket(bucketName)
	obj := bucket.Object(objectName)
	r, err := obj.NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func generateSHA1Hash(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func decrypt(data string, passphrase string) ([]byte, error) {
	ciphertext, _ := base64.URLEncoding.DecodeString(data)
	key := []byte(PadKey(passphrase))

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func main() {
	// Read the passphrase from environment variable
	passphrase := os.Getenv("DECRYPTION_PASSPHRASE")
	if passphrase == "" {
		log.Fatal("DECRYPTION_PASSPHRASE environment variable not set")
	}

	encryptedData, err := ioutil.ReadFile("credentials.json.enc")
	if err != nil {
		log.Fatalf("Failed to read encrypted credentials file: %v", err)
	}

	decryptedData, err := decrypt(string(encryptedData), passphrase)
	if err != nil {
		log.Fatalf("Failed to decrypt credentials file: %v", err)
	}

	tempFile, err := ioutil.TempFile("", "credentials-*.json")
	if err != nil {
		log.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write(decryptedData); err != nil {
		log.Fatalf("Failed to write decrypted data to temp file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		log.Fatalf("Failed to close temp file: %v", err)
	}

	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithCredentialsFile(tempFile.Name()))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	http.HandleFunc("/flutter/release/", func(w http.ResponseWriter, r *http.Request) {
		requestedPath := r.URL.Path[len("/flutter/release/"):]
		bucketName := "android-flutter-artifacts"

		log.Printf("Received request: %s", r.URL.Path)

		data, err := downloadFromGCS(ctx, client, bucketName, requestedPath)
		if err != nil {
			if errors.Is(err, storage.ErrObjectNotExist) {
				log.Printf("File not found: %s", requestedPath)
				http.NotFound(w, r)
			} else {
				log.Printf("Error downloading file: %s", err)
				http.Error(w, "Error downloading file", http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	})

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}

		aarFile, _, err := r.FormFile("aar")
		if err != nil {
			http.Error(w, "Error getting .aar file", http.StatusBadRequest)
			return
		}
		defer aarFile.Close()

		groupID := r.FormValue("groupID")
		artifactID := r.FormValue("artifactID")
		version := r.FormValue("version")
		bucketName := r.FormValue("bucketName")

		if groupID == "" {
			http.Error(w, "groupID is required", http.StatusBadRequest)
			return
		}
		if artifactID == "" {
			http.Error(w, "artifactID is required", http.StatusBadRequest)
			return
		}
		if version == "" {
			http.Error(w, "version is required", http.StatusBadRequest)
			return
		}
		if bucketName == "" {
			http.Error(w, "bucketName is required", http.StatusBadRequest)
			return
		}

		groupIDPath := strings.ReplaceAll(groupID, ".", "/")

		aarDestPath := fmt.Sprintf("%s/%s/%s/%s-%s.aar", groupIDPath, artifactID, version, artifactID, version)
		pomDestPath := fmt.Sprintf("%s/%s/%s/%s-%s.pom", groupIDPath, artifactID, version, artifactID, version)

		err = uploadToGCS(ctx, client, bucketName, aarDestPath, aarFile)
		if err != nil {
			http.Error(w, "Error uploading .aar file to GCS", http.StatusInternalServerError)
			return
		}

		pomContent := generatePOMContent(groupID, artifactID, version)

		err = uploadToGCS(ctx, client, bucketName, pomDestPath, strings.NewReader(pomContent))
		if err != nil {
			http.Error(w, "Error uploading POM file to GCS", http.StatusInternalServerError)
			return
		}

		aarSHA1 := generateSHA1Hash(aarDestPath)
		pomSHA1 := generateSHA1Hash(pomContent)

		err = uploadToGCS(ctx, client, bucketName, aarDestPath+".sha1", strings.NewReader(aarSHA1))
		if err != nil {
			http.Error(w, "Error uploading .aar SHA1 file to GCS", http.StatusInternalServerError)
			return
		}

		err = uploadToGCS(ctx, client, bucketName, pomDestPath+".sha1", strings.NewReader(pomSHA1))
		if err != nil {
			http.Error(w, "Error uploading POM SHA1 file to GCS", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Files and POM uploaded successfully!")
	})

	log.Println("Starting server on :8080")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
