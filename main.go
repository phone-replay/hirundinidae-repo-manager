package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// Function to generate the POM file content
func generatePOMContent(groupId, artifactId, version string) string {
	// Replace slashes with dots in groupId
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

// Function to upload a file to GCS
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

// Function to download a file from GCS
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

// Function to generate SHA1 hash for a string
func generateSHA1Hash(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	bucketName := "android-flutter-artifacts" // Replace with your GCS bucket name

	// Create a storage client
	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithCredentialsFile("credentials.json"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestedPath := r.URL.Path[1:] // Remove the leading '/'

		log.Printf("Received request: %s", r.URL.Path)

		data, err := downloadFromGCS(ctx, client, bucketName, requestedPath)
		if err != nil {
			if err == storage.ErrObjectNotExist {
				log.Printf("File not found: %s", requestedPath)
				http.NotFound(w, r)
			} else {
				log.Printf("Error downloading file: %s", err)
				http.Error(w, "Error downloading file", http.StatusInternalServerError)
			}
			return
		}

		// Serve the file data
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	})

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseMultipartForm(10 << 20) // 10 MB limit
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
		if groupID == "" || artifactID == "" || version == "" {
			http.Error(w, "groupID, artifactID, and version are required", http.StatusBadRequest)
			return
		}

		// Replace dots in groupID for GCS compatibility
		groupIDPath := strings.ReplaceAll(groupID, ".", "/")

		// Define the destination paths for GCS
		aarDestPath := fmt.Sprintf("%s/%s/%s/%s-%s.aar", groupIDPath, artifactID, version, artifactID, version)
		pomDestPath := fmt.Sprintf("%s/%s/%s/%s-%s.pom", groupIDPath, artifactID, version, artifactID, version)

		// Upload .aar file to GCS
		err = uploadToGCS(ctx, client, bucketName, aarDestPath, aarFile)
		if err != nil {
			http.Error(w, "Error uploading .aar file to GCS", http.StatusInternalServerError)
			return
		}

		// Generate the POM file content
		pomContent := generatePOMContent(groupID, artifactID, version)

		// Upload the POM file to GCS
		err = uploadToGCS(ctx, client, bucketName, pomDestPath, strings.NewReader(pomContent))
		if err != nil {
			http.Error(w, "Error uploading POM file to GCS", http.StatusInternalServerError)
			return
		}

		// Generate and upload SHA1 files
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
	log.Fatal(http.ListenAndServe(":8080", nil))
}