package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"

	"github.com/jpignata/toolbox/pkg/ssm"
)

const (
	key     = "aoc_session_token"
	baseURL = "https://adventofcode.com"
	cookie  = "session"
)

func main() {
	var year string

	if len(os.Args) == 1 {
		fmt.Println("Usage: aoc day [year]")
		os.Exit(1)
	}

	day := os.Args[1]

	if len(os.Args) == 3 {
		year = os.Args[2]
	} else {
		year = fmt.Sprintf("%d", time.Now().Year())
	}

	uri, err := url.Parse(
		fmt.Sprintf("%s/%s/day/%s/input", baseURL, year, day),
	)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	token, err := ssm.GetSecureString(key)

	if err != nil {
		fmt.Printf("Couldn't get SecretString (%s): %s\n", key, err)
		os.Exit(1)
	}

	body, err := get(uri, token)

	if err != nil {
		fmt.Printf("Couldn't fetch URL (%s): %s\n", uri.String(), err)
		os.Exit(1)
	}

	fmt.Print(body)
}

func get(uri *url.URL, token string) (string, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	cookie := &http.Cookie{
		Name:  cookie,
		Value: token,
	}

	jar.SetCookies(uri, []*http.Cookie{cookie})
	resp, err := client.Get(uri.String())

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	input, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", errors.New(string(input))
	}

	return string(input), err
}
