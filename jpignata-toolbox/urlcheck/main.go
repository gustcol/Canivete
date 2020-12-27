package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"

	"golang.org/x/time/rate"
)

type status int

type result struct {
	Code     int
	Location string
	Status   status
	URL      string
	Error    error
}

const (
	success status = iota
	redirect
	other
	unknown
)

var (
	client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func main() {
	concurrency := flag.Int("workers", 5, "Number of concurrent workers")
	rps := flag.Int("max", 25, "Maximum requests per second")
	flag.Parse()

	limiter := rate.NewLimiter(rate.Limit(*rps), 1)
	queue := make(chan string)
	scanner := bufio.NewScanner(os.Stdin)
	wg := &sync.WaitGroup{}

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for url := range queue {
				limiter.Wait(context.Background())

				result := request(url)

				if result.Status == redirect {
					fmt.Printf("StatusCode:%d URL:%s Location:%s\n", result.Code, result.URL, result.Location)
				} else if result.Status == unknown {
					fmt.Printf("StatusCode:0 URL:%s Error:%s\n", result.URL, result.Error)
				} else {
					fmt.Printf("StatusCode:%d URL:%s\n", result.Code, result.URL)
				}
			}
		}()
	}

	for scanner.Scan() {
		queue <- scanner.Text()
	}

	close(queue)
	wg.Wait()
}

func request(uri string) result {
	res, err := client.Head(uri)

	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return result{
			Status: success,
			Code:   res.StatusCode,
			URL:    uri,
		}
	case (res.StatusCode >= 301 && res.StatusCode <= 303) || res.StatusCode == 307:
		return result{
			Status:   redirect,
			Code:     res.StatusCode,
			Location: res.Header.Get("location"),
			URL:      uri,
		}
	case err != nil:
		return result{
			Status: unknown,
			URL:    uri,
			Error:  err,
		}
	default:
		return result{
			Status: other,
			Code:   res.StatusCode,
			URL:    uri,
		}
	}
}
