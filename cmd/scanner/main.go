package main

import (
	"flag"
	"fmt"
	"os"

	"bitbucket-secrets-scanner/internal/bitbucket"
	"bitbucket-secrets-scanner/internal/output"
	"bitbucket-secrets-scanner/internal/scanner"
)

func main() {
	var (
		baseURL       string
		httpToken     string
		projectKey    string
		repoSlug      string
		commitID      string
		filePath      string
		localFilePath string
		localDirPath  string
		outputFile    string
	)

	// Define command line flags
	flag.StringVar(&baseURL, "url", "", "Bitbucket Data Center base URL (e.g., https://bitbucket.example.com)")
	flag.StringVar(&httpToken, "token", "", "Bitbucket HTTP token")
	flag.StringVar(&projectKey, "project", "", "Bitbucket project key")
	flag.StringVar(&repoSlug, "repo", "", "Bitbucket repository slug")
	flag.StringVar(&commitID, "commit", "", "Bitbucket commit ID")
	flag.StringVar(&filePath, "file", "", "Bitbucket file path to scan")
	flag.StringVar(&localFilePath, "local-file", "", "Local file to scan")
	flag.StringVar(&localDirPath, "local-dir", "", "Local directory to scan")
	flag.StringVar(&outputFile, "output", "secrets.csv", "Output CSV file path")

	flag.Parse()

	// Validate flags
	if !(localFilePath == "" ||
		localDirPath == "" ||
		(baseURL == "" &&
			httpToken == "" &&
			projectKey == "" &&
			repoSlug == "" &&
			filePath == "" &&
			commitID == "")) {
		fmt.Println("Error: You must either specify a local file/directory to scan or provide Bitbucket repository details")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Initialize CSV writer
	csvWriter, err := output.NewCSVWriter(outputFile)
	if err != nil {
		fmt.Printf("Error initializing CSV writer: %v\n", err)
		os.Exit(1)
	}
	defer csvWriter.Close()

	// Initialize the secret detector
	detector := scanner.NewSecretDetector()

	var secrets []scanner.Secret

	// Process files based on input flags
	if localFilePath != "" {
		// Scan a single local file
		localScanner := scanner.NewFileScanner(detector)
		fileSecrets, err := localScanner.ScanFile(localFilePath)
		if err != nil {
			fmt.Printf("Error scanning local file: %v\n", err)
			os.Exit(1)
		}
		secrets = append(secrets, fileSecrets...)
	} else if localDirPath != "" {
		// Scan all files in a local directory
		localScanner := scanner.NewDirectoryScanner(detector)
		fileSecrets, err := localScanner.ScanDirectory(localDirPath)
		if err != nil {
			fmt.Printf("Error scanning local directory: %v\n", err)
			os.Exit(1)
		}
		secrets = append(secrets, fileSecrets...)
	} else {
		// Initialize BitBucket client
		client := bitbucket.NewClient(baseURL, httpToken)

		// Get Bitbucket commit info
		commit, err := client.GetCommit(projectKey, repoSlug, commitID)
		if err != nil {
			fmt.Printf("Error getting commit info: %v\n", err)
			os.Exit(1)
		}

		bitbucketScanner := scanner.NewBitbucketScanner(client, detector)

		if filePath != "" {
			// Scan a single Bitbucket file
			fileSecrets, err := bitbucketScanner.ScanBitbucketFile(projectKey, repoSlug, commitID, filePath, commit)
			if err != nil {
				fmt.Printf("Error scanning Bitbucket file: %v\n", err)
				os.Exit(1)
			}
			secrets = append(secrets, fileSecrets...)
		} else {
			// Scan all files in the commit
			fileList, err := client.GetFileList(projectKey, repoSlug, commitID)
			if err != nil {
				fmt.Printf("Error getting file list: %v\n", err)
				os.Exit(1)
			}

			for _, file := range fileList {
				if file.Type == "FILE" {
					fileSecrets, err := bitbucketScanner.ScanBitbucketFile(projectKey, repoSlug, commitID, file.Path, commit)
					if err != nil {
						fmt.Printf("Warning: Error scanning file %s: %v\n", file.Path, err)
						continue
					}
					secrets = append(secrets, fileSecrets...)
				}
			}
		}
	}

	// Write secrets to CSV
	if err := csvWriter.WriteSecrets(secrets); err != nil {
		fmt.Printf("Error writing to CSV: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scan complete. Found %d secrets. Results written to %s\n", len(secrets), outputFile)
}
