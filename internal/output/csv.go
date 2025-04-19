package output

import (
	"encoding/csv"
	"fmt"
	"os"

	"bitbucket-secrets-scanner/internal/scanner"
)

// CSVWriter handles writing scan results to a CSV file
type CSVWriter struct {
	file   *os.File
	writer *csv.Writer
}

// NewCSVWriter creates a new CSV writer
func NewCSVWriter(filePath string) (*CSVWriter, error) {
	file, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}

	writer := csv.NewWriter(file)

	// Write header
	header := []string{"project_key", "repository_slug", "commit_id", "commit_date", "commit_author", "filename", "line_number", "secret_type", "secret_value"}
	if err := writer.Write(header); err != nil {
		file.Close()
		return nil, err
	}
	writer.Flush()

	return &CSVWriter{
		file:   file,
		writer: writer,
	}, nil
}

// WriteSecrets writes secrets to the CSV file
func (w *CSVWriter) WriteSecrets(secrets []scanner.Secret) error {
	for _, secret := range secrets {
		row := []string{
			secret.ProjectKey,
			secret.RepositorySlug,
			secret.CommitID,
			secret.CommitDate,
			secret.CommitAuthor,
			secret.Filename,
			fmt.Sprintf("%d", secret.LineNumber),
			secret.SecretType,
			secret.SecretValue,
		}
		if err := w.writer.Write(row); err != nil {
			return err
		}
	}

	w.writer.Flush()
	return w.writer.Error()
}

// Close closes the CSV file
func (w *CSVWriter) Close() error {
	w.writer.Flush()
	return w.file.Close()
}
