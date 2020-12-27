package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/jpignata/toolbox/pkg/ssm"
)

const (
	key      = "bitly_token"
	endpoint = "https://api-ssl.bitly.com/v4/bitlinks"
)

// Bitlink represents a shortened URL. (https://dev.bitly.com/v4_documentation.html)
type Bitlink struct {
	URL string
}

// String returns a URL for the Bitlink, defaulting the protocol to https if not provided.
func (b Bitlink) String() string {
	u, err := url.Parse(b.URL)

	if err != nil {
		return b.URL
	}

	if u.Scheme == "" {
		u.Scheme = "https"
	}

	return u.String()
}

type request struct {
	LongURL string `json:"long_url"`
}

type response struct {
	Link string `json:"link"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: bitly [url]")
		os.Exit(1)
	}

	token, err := ssm.GetSecureString(key)

	if err != nil {
		fmt.Printf("Couldn't read SecretString (%s): %s\n", key, err)
		os.Exit(1)
	}

	location, err := create(token, Bitlink{os.Args[1]})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(location)
}

func create(token string, bitlink Bitlink) (string, error) {
	var r response

	body, err := json.Marshal(request{bitlink.String()})

	if err != nil {
		return "", err
	}

	client := &http.Client{}
	req, _ := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := client.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errBody, _ := ioutil.ReadAll(resp.Body)

		return "", errors.New(string(errBody))
	}

	b, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	err = json.Unmarshal(b, &r)

	if err != nil {
		return "", err
	}

	return r.Link, nil
}
