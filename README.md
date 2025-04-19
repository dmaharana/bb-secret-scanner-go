This Golang command line application scans for secrets in files from Bitbucket Data Center repositories or local files/directories. Here's how to use it:

### Features:

- Scan a single file or entire directory from Bitbucket repository
- Scan local files or directories
- Detect various types of secrets using regex patterns
- Output results to a CSV file with the required headers

### Usage Examples:

**Scan a Bitbucket file:**

```
./bitbucket-secret-scanner \
  --url https://bitbucket.example.com \
  --token YOUR_HTTP_TOKEN \
  --project PROJECT_KEY \
  --repo REPOSITORY_SLUG \
  --commit COMMIT_ID \
  --file path/to/file.js \
  --output results.csv
```

**Scan all files in a Bitbucket commit:**

```
./bitbucket-secret-scanner \
  --url https://bitbucket.example.com \
  --token YOUR_HTTP_TOKEN \
  --project PROJECT_KEY \
  --repo REPOSITORY_SLUG \
  --commit COMMIT_ID \
  --output results.csv
```

**Scan a local file:**

```
./bitbucket-secret-scanner \
  --local-file path/to/file.js \
  --output results.csv
```

**Scan a local directory:**

```
./bitbucket-secret-scanner \
  --local-dir path/to/directory \
  --output results.csv
```

### Notes:

- The application uses Bitbucket REST API with bearer token authentication
- It detects common secrets like API keys, passwords, private keys, tokens, etc.
- Results include project, repo, commit details, filename, line number and the secret value
- For simplicity, this implementation doesn't handle pagination for large repositories (you might need to extend it for very large repos)
