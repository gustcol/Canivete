package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/jpignata/toolbox/pkg/ssm"
)

const (
	key = "github_personal_access_token"
	url = "https://api.github.com/gists"
)

// Gist represents a GitHub Gist (https://gist.github.com).
type Gist struct {
	Files       map[string]File `json:"files"`
	Description string          `json:"description"`
	Public      bool            `json:"public"`
}

// File represents GitHub's desired structure for posting a file's contents to the Gist API.
type File struct {
	Content string `json:"content"`
}

type files []string

// Response represents attributes passed back for the Gist API.
type Response struct {
	URL string `json:"html_url"`
}

// Set adds a new file to files.
func (f *files) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// String returns a comma-separated list of passed files.
func (f files) String() string {
	return strings.Join(f, ", ")
}

func main() {
	var f files
	var n, d string
	var p bool

	flag.Var(&f, "f", "filename to gist (can be specified multiple times)")
	flag.StringVar(&n, "n", "", "filename for stdin content")
	flag.BoolVar(&p, "p", false, "make gist public (private if absent)")
	flag.StringVar(&d, "d", "", "gist description")
	flag.Parse()

	files, err := readFiles(f)

	if err != nil {
		fmt.Printf("Couldn't read files: %s\n", err)
		os.Exit(1)
	}

	stdin, err := readStdin()

	if err != nil {
		fmt.Printf("Couldn't read stdin: %s\n", err)
		os.Exit(1)
	}

	if len(stdin) > 0 {
		files[n] = File{stdin}
	}

	credentials, err := ssm.GetSecureString(key)

	if err != nil {
		fmt.Printf("Couldn't read SecretString (%s): %s\n", key, err)
		os.Exit(1)
	}

	location, err := create(credentials, Gist{
		Files:       files,
		Description: d,
		Public:      p,
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(location)
}

func readFiles(filenames []string) (map[string]File, error) {
	files := make(map[string]File)

	for _, filename := range filenames {
		body, err := ioutil.ReadFile(filename)

		if err != nil {
			return files, err
		}

		parts := strings.Split(filename, "/")
		files[parts[len(parts)-1]] = File{string(body)}
	}

	return files, nil
}

func readStdin() (string, error) {
	stat, err := os.Stdin.Stat()

	if err != nil {
		return "", err
	}

	if stat.Mode()&os.ModeCharDevice == 0 {
		body, err := ioutil.ReadAll(os.Stdin)

		return string(body), err
	}

	return "", nil
}

func create(credentials string, gist Gist) (string, error) {
	reqBody, err := json.Marshal(gist)

	if err != nil {
		return "", err
	}

	client := &http.Client{}
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	parts := strings.Split(credentials, ":")
	req.SetBasicAuth(parts[0], parts[1])

	resp, err := client.Do(req)

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		errBody, _ := ioutil.ReadAll(resp.Body)

		return "", errors.New(string(errBody))
	}

	var respJSON Response
	respBody, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(respBody, &respJSON)

	return respJSON.URL, nil
}
