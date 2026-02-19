package utils

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func GetIPAddressesWithHint(hintRegex string) ([]string, error) {
	var ipAddresses []string

	hint, err := regexp.Compile(hintRegex)
	if err != nil {
		return nil, err
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip := ipnet.IP.To4(); ip != nil {
				if hint.MatchString(ip.String()) {
					ipAddresses = append(ipAddresses, ip.String())
				}
			}
		}
	}

	return ipAddresses, nil
}

func GetPublicIPAddress() (string, error) {
	resultChan := make(chan string, 2)
	errChan := make(chan error, 2)

	// Method 1: Using OpenDNS
	go func() {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, "resolver1.opendns.com:53")
			},
		}
		ip, err := r.LookupHost(context.Background(), "myip.opendns.com")
		if err != nil {
			errChan <- err
			return
		}
		if len(ip) > 0 {
			resultChan <- ip[0]
		} else {
			errChan <- fmt.Errorf("no IP address found")
		}
	}()

	// Method 2: Using config.co
	go func() {
		req, err := http.NewRequest("GET", "http://ifconfig.co/ip", nil)
		if err != nil {
			errChan <- err
			return
		}
		req.Header.Set("Host", "ifconfig.co")

		client := &http.Client{
			Timeout: time.Second * 10,
		}
		resp, err := client.Do(req)
		if err != nil {
			errChan <- err
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- strings.TrimSpace(string(body))
	}()

	var finalErr error
	for i := 0; i < 2; i++ {
		select {
		case result := <-resultChan:
			return result, nil
		case err := <-errChan:
			finalErr = err
		case <-time.After(15 * time.Second):
			return "", fmt.Errorf("timeout waiting for IP address")
		}
	}

	return "", finalErr
}
