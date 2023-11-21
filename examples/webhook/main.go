package main

import (
	"encoding/json"
	"fmt"
	"github.com/zema1/watchvuln/grab"
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

	http.HandleFunc("/webhook", handleWebhookData)

	if err := http.ListenAndServe(addr, http.DefaultServeMux); err != nil {
		panic(err)
	}
}

type WebhookData struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

func handleWebhookData(writer http.ResponseWriter, request *http.Request) {
	data, err := io.ReadAll(request.Body)
	if err != nil {
		fmt.Println(err)
		writer.WriteHeader(500)
		return
	}

	// get message type
	var wd WebhookData
	if err := json.Unmarshal(data, &wd); err != nil {
		writeErr(writer, err)
		return
	}
	fmt.Println()

	switch wd.Type {
	case push.RawMessageTypeInitial:
		fmt.Println("recv initial data:")
		var msg push.InitialMessage
		if err := json.Unmarshal(wd.Content, &msg); err != nil {
			writeErr(writer, err)
			return
		}
		fmt.Printf("msg: %s\n", string(wd.Content))
		fmt.Printf("unmarshal: %+v\n", msg)
	case push.RawMessageTypeText:
		fmt.Println("recv text data:")
		var msg push.TextMessage
		if err := json.Unmarshal(wd.Content, &msg); err != nil {
			writeErr(writer, err)
			return
		}
		fmt.Printf("msg: %s\n", string(wd.Content))
		//fmt.Printf("unmarshal: %+v\n", msg)
	case push.RawMessageTypeVulnInfo:
		fmt.Println("recv vuln data:")
		var msg grab.VulnInfo
		if err := json.Unmarshal(wd.Content, &msg); err != nil {
			writeErr(writer, err)
			return
		}
		fmt.Printf("msg: %s\n", string(wd.Content))
		//fmt.Printf("unmarshal: %+v\n", msg)
	default:
		fmt.Println("recv unknown data:")
		fmt.Println(string(data))
	}
}

func writeErr(writer http.ResponseWriter, err error) {
	fmt.Println(err)
	writer.WriteHeader(500)
	writer.Write([]byte(err.Error()))
}
