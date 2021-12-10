/*
 * HMAC-SHA256 signature algorithm example
 * Example operation mode:
 *
 * Set the directory path where the sample.go file is located to the environment variable GOPATH, and then execute the following command
 *
 * windows:
 * go build sample.go && sample.exe
 *
 * linux:
 * go build sample.go && ./sample
 *
 * @author yorker
 * @created 2020-3-14
 */

package main

import (
	"bytes"
	"fmt"
	"hmac_auth"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	username := "<HMAC account>"
	secretkey := "<HMAC secret>"

	//
	//POST request method begin
	//
	fmt.Println("====> Start POST Request")

	//Request body
	body := []byte("request data in body")

	//Start signing, get the HTTP HEADER related to the signature field
	header := hmac_auth.GetAuthHeader(username, secretkey, body)
	//fmt.Println(header)

	url := "<Interface address with hmac authentication>"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Println(err.Error())
		return
	}

	//Set head
	for k, v := range header {
		req.Header.Set(k, v)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err.Error())
		return
	}

	fmt.Println(string(content))
	fmt.Println("<==== POST Request END")

	//
	//GET request method begin
	//
	fmt.Println("\n\n====> Start GET Request")

	//Start signing, get the HTTP HEADER related to the signature field
	header = konghmac.GetAuthHeader(username, secretkey, nil)
	//fmt.Println(header)

	req, err = http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Println(err.Error())
		return
	}

	//Set head
	for k, v := range header {
		req.Header.Set(k, v)
	}

	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer resp.Body.Close()

	content, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err.Error())
		return
	}

	fmt.Println(string(content))
	fmt.Println("<==== GET Request END")

}
