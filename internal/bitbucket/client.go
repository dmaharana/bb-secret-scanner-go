package bitbucket

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Client represents a Bitbucket REST API client
type Client struct {
	BaseURL string
	Token   string
	client  *http.Client
}

// NewClient creates a new Bitbucket client
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		client:  &http.Client{},
	}
}

// GetCommit fetches commit information from Bitbucket
func (c *Client) GetCommit(projectKey, repoSlug, commitID string) (Commit, error) {
	var commit Commit

	url := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s/commits/%s", c.BaseURL, projectKey, repoSlug, commitID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return commit, err
	}

	req.Header.Add("Authorization", "Bearer "+c.Token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return commit, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return commit, fmt.Errorf("API request failed with status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return commit, err
	}

	err = json.Unmarshal(body, &commit)
	if err != nil {
		return commit, err
	}

	return commit, nil
}

// GetFileList fetches a list of files in a commit
func (c *Client) GetFileList(projectKey, repoSlug, commitID string) ([]File, error) {
	var files []File

	url := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s/browse?at=%s", c.BaseURL, projectKey, repoSlug, commitID)

	// This is a simplification - in real implementation we'd need to handle pagination
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return files, err
	}

	req.Header.Add("Authorization", "Bearer "+c.Token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return files, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return files, fmt.Errorf("API request failed with status code %d", resp.StatusCode)
	}

	var response struct {
		Values []struct {
			Path string `json:"path"`
			Type string `json:"type"` // "FILE" or "DIRECTORY"
		} `json:"values"`
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return files, err
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return files, err
	}

	for _, value := range response.Values {
		files = append(files, File{
			Path: value.Path,
			Type: value.Type,
		})
	}

	return files, nil
}

// GetFileContent fetches the content of a file
func (c *Client) GetFileContent(projectKey, repoSlug, commitID, filePath string) (string, error) {
	url := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s/raw/%s?at=%s",
		c.BaseURL, projectKey, repoSlug, filePath, commitID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", "Bearer "+c.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
