package main

import (
	"encoding/json"
	"fmt"
	"github.com/zema1/watchvuln/push"
	"io"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) == 1 {
		fmt.Printf("Usage: %s listen-addr\nex: %s 127.0.0.1:1111\n", os.Args[0], os.Args[0])
		os.Exit(0)
	}
	addr := os.Args[1]
	fmt.Printf("webhook server url: %s\n", fmt.Sprintf("http://%s/webhook", addr))
	http.HandleFunc("/webhook", func(writer http.ResponseWriter, request *http.Request) {
		data, err := io.ReadAll(request.Body)
		if err != nil {
			fmt.Println(err)
			writer.WriteHeader(500)
			return
		}
		var vulnData push.WebhookData
		if err := json.Unmarshal(data, &vulnData); err != nil {
			fmt.Println(err)
			writer.WriteHeader(500)
			return
		}

		fmt.Println("===========")
		fmt.Printf("type: %s\ntitle: %s\ncontent: %s\n", vulnData.Type, vulnData.Title, vulnData.Content)
	})
	if err := http.ListenAndServe(addr, http.DefaultServeMux); err != nil {
		panic(err)
	}
}
