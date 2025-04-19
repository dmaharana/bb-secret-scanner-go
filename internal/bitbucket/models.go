package bitbucket

// File represents a file in Bitbucket
type File struct {
	Path string
	Type string // "FILE" or "DIRECTORY"
}

// Commit represents a commit in Bitbucket
type Commit struct {
	ID        string    `json:"id"`
	AuthorObj AuthorObj `json:"author"`
	Date      string    `json:"authorTimestamp"`
}

// AuthorObj represents the author of a commit
type AuthorObj struct {
	Name  string `json:"name"`
	Email string `json:"emailAddress"`
}
