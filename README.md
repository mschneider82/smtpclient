# smtpclient

A modern, context-aware ESMTP and LMTP client for Go.

This package is a fork of [emersion/go-smtp](https://github.com/emersion/go-smtp) client package, modernized with full context support, detailed responses, and improved flexibility.

### Key Features and Improvements

*   **Full Context Support**: All network operations (Dial, Hello, Auth, Mail, Rcpt, Data, etc.) now accept a `context.Context` for proper timeout and cancellation handling.
*   **Detailed Responses**: Every command returns a `Response` object containing the SMTP status code, the enhanced status code (if provided by the server), and the full text message.
*   **Modernized API**: 
    *   Uses `errors.Is` and `errors.As` for robust error handling.
    *   Simplified connection management with `DialContext` and `HandshakeContext`.
    *   Removed hardcoded magic strings where possible.
*   **Comprehensive SMTP Options**: Full support for MAIL FROM and RCPT TO extensions (SIZE, SMTPUTF8, BODY, RET, ENVID, AUTH, REQUIRETLS, NOTIFY, ORCPT, etc.).
*   **LMTP Support**: Built-in support for the Local Mail Transfer Protocol (RFC 2033), including per-recipient response codes after the DATA command.
*   **Security & Robustness**:
    *   Configurable line length limits to prevent buffer overflows (RFC 5321 compliant by default).
    *   Explicit connection state tracking to prevent double-closing or redundant operations.
    *   Access to underlying TLS state and network addresses.

### Installation

```bash
go get schneider.vip/smtpclient
```

### Usage Example

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"schneider.vip/smtpclient"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to the server
	opts := smtpclient.DefaultOptions()
	client, resp, err := smtpclient.Dial(ctx, "mail.example.com:587", opts)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	fmt.Printf("Connected: %s\n", resp)

	// Say Hello
	resp, err = client.Hello(ctx, "localhost")
	if err != nil {
		log.Fatal(err)
	}

	// Start TLS if supported
	if ok, _ := client.Extension("STARTTLS"); ok {
		resp, err = client.StartTLS(ctx, nil)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Send a mail
	resp, err = client.Mail(ctx, "sender@example.com", nil)
	if err != nil {
		log.Fatal(err)
	}

	resp, err = client.Rcpt(ctx, "recipient@example.com", nil)
	if err != nil {
		log.Fatal(err)
	}

	wc, resp, err := client.Data(ctx)
	if err != nil {
		log.Fatal(err)
	}

	_, err = fmt.Fprintf(wc, "Subject: Hello\r\n\r\nThis is a test message.")
	if err != nil {
		log.Fatal(err)
	}

	// Close the writer and get the server response
	dataResp, err := wc.CloseWithResponse()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Queued: %s\n", dataResp.StatusText)

	// Quit gracefully
	client.Quit(ctx)
}
```

#### Direct Delivery via MX Lookup

If you want to deliver mail directly to the recipient's mail server without knowing the exact host beforehand, you can use `DialMX`.

```go
	rcpts := []string{"recipient@example.com"}
	client, resp, err := smtpclient.DialMX(ctx, rcpts, smtpclient.DefaultOptions())
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
```

### License

MIT - See [LICENSE](LICENSE) for details.
Original work by emersion and others. Improvements by Matthias Schneider.
