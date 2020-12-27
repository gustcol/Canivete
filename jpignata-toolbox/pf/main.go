package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/net/html"
)

// Link holds the contents of a <link> tag.
type Link struct {
	Rel      string
	Href     string
	Hreflang string
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: pf url")
		os.Exit(1)
	}

	u, err := url.Parse(os.Args[1])

	if err != nil {
		fmt.Printf("Could not parse URL: %s", err)
		os.Exit(1)
	}

	if len(u.Scheme) == 0 {
		u.Scheme = "https"
	}

	times, statusCode, body, location, err := get(u.String())
	statusText := http.StatusText(statusCode)

	if err != nil {
		fmt.Printf("Could not fetch URL: %s", err)
		os.Exit(1)
	}

	title, description, header, canonical, alternates, err := parse(body)

	if err != nil {
		fmt.Printf("Could not parse HTML: %s", err)
		os.Exit(1)
	}

	if statusCode == 200 {
		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 0, 4, ' ', 0)

		fmt.Fprintf(w, "response\t%d %s [connect=%s firstByte=%s total=%s]\t\n", statusCode, statusText, times[0],
			times[1], times[2])
		fmt.Fprintf(w, "title\t%s\n", strings.TrimSpace(title))

		if len(strings.TrimSpace(header)) > 0 {
			fmt.Fprintf(w, "h1\t%s\n", strings.TrimSpace(header))
		}

		if len(strings.TrimSpace(description)) > 0 {
			fmt.Fprintf(w, "description\t%s\t\n", strings.TrimSpace(description))
		}

		fmt.Fprintf(w, "url\t%s\n", u.String())

		if len(canonical) > 0 {
			fmt.Fprintf(w, "canonical\t%s\n", canonical)
		}

		if len(alternates) > 0 {
			for locale, url := range alternates {
				fmt.Fprintf(w, "alternate [%s]\t%s\n", locale, url)
			}
		}

		w.Flush()
	} else {
		fmt.Printf("%d %s\n", statusCode, statusText)

		if len(location) > 0 {
			fmt.Printf("Location: %s\n", location)
		}
	}
}

func get(u string) (times []time.Duration, statusCode int, body io.ReadCloser, location string, err error) {
	var connectTime, firstByteTime time.Time

	start := time.Now()
	req, _ := http.NewRequest("GET", u, nil)
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			connectTime = time.Now()
		},
		GotFirstResponseByte: func() {
			firstByteTime = time.Now()
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := http.DefaultTransport.RoundTrip(req)

	if err != nil {
		return
	}

	times = append(times, connectTime.Sub(start), firstByteTime.Sub(start), time.Since(start))
	statusCode = resp.StatusCode
	body = resp.Body
	location = resp.Header.Get("location")

	return
}

func parse(body io.ReadCloser) (title, description, header, canonical string,
	alternates map[string]string, err error) {
	var links []Link
	var f func(*html.Node)

	alternates = make(map[string]string)
	root, err := html.Parse(body)

	if err != nil {
		return
	}

	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			var link Link

			if n.Data == "link" {
				for _, a := range n.Attr {
					switch a.Key {
					case "rel":
						link.Rel = a.Val
					case "href":
						link.Href = a.Val
					case "hreflang":
						link.Hreflang = a.Val
					}
				}

				links = append(links, link)
			} else if n.Data == "h1" {
				header = n.FirstChild.Data
			} else if n.Data == "title" {
				title = n.FirstChild.Data
			} else if n.Data == "meta" {
				for _, a := range n.Attr {
					if a.Key == "name" && a.Val == "description" {
						for _, a := range n.Attr {
							if a.Key == "content" {
								description = a.Val
							}
						}
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}

	f(root)

	for _, link := range links {
		switch link.Rel {
		case "canonical":
			canonical = link.Href
		case "alternate":
			if len(link.Hreflang) > 0 {
				alternates[link.Hreflang] = link.Href
			}
		}
	}

	return
}
