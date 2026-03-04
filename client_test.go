package smtpclient

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBasic(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		c.Write([]byte("220 welcome\r\n"))

		buf := make([]byte, 1024)
		n, _ := c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "EHLO") {
			c.Write([]byte("250-hello\r\n250 AUTH PLAIN\r\n"))
		}

		n, _ = c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "MAIL FROM") {
			c.Write([]byte("250 2.1.0 Ok\r\n"))
		}

		n, _ = c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "RCPT TO") {
			c.Write([]byte("250 2.1.5 Ok\r\n"))
		}

		n, _ = c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "DATA") {
			c.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
		}

		n, _ = c.Read(buf)
		// data...
		c.Write([]byte("250 2.0.0 Ok: queued as 12345\r\n"))

		n, _ = c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "QUIT") {
			c.Write([]byte("221 2.0.0 Bye\r\n"))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, resp, err := Dial(ctx, l.Addr().String(), DefaultOptions())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if resp.Code != 220 {
		t.Errorf("Expected 220, got %v", resp.Code)
	}

	resp, err = client.Hello(ctx, "localhost")
	if err != nil {
		t.Errorf("Hello failed: %v", err)
	}

	resp, err = client.Mail(ctx, "sender@example.com", nil)
	if err != nil {
		t.Errorf("Mail failed: %v", err)
	}
	if resp.EnhancedCode != (EnhancedCode{2, 1, 0}) {
		t.Errorf("Expected 2.1.0, got %v", resp.EnhancedCode)
	}

	resp, err = client.Rcpt(ctx, "recipient@example.com", nil)
	if err != nil {
		t.Errorf("Rcpt failed: %v", err)
	}

	w, resp, err := client.Data(ctx)
	if err != nil {
		t.Errorf("Data failed: %v", err)
	}
	io.WriteString(w, "Subject: Test\r\n\r\nHello!")
	err = w.Close()
	if err != nil {
		t.Errorf("Data Close failed: %v", err)
	}

	resp, err = client.Quit(ctx)
	if err != nil {
		t.Errorf("Quit failed: %v", err)
	}
}

func TestContextTimeout(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("220 welcome\r\n"))
		// Just hang
		time.Sleep(2 * time.Second)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	client, _, err := Dial(ctx, l.Addr().String(), DefaultOptions())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	_, err = client.Hello(ctx, "localhost")
	if err == nil {
		t.Error("Expected error due to timeout, got nil")
	}
	if err != context.DeadlineExceeded && !strings.Contains(err.Error(), "closed network connection") && !strings.Contains(err.Error(), "i/o timeout") {
		t.Errorf("Expected context.DeadlineExceeded or timeout error, got %v", err)
	}
}

func TestLineLimitDial(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		// Sende eine Zeile, die definitiv länger als 10 Zeichen ist
		c.Write([]byte("220 " + strings.Repeat("A", 100) + "\r\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := DefaultOptions()
	opts.LineLimit = 10 // Sehr kleines Limit

	client, _, err := Dial(ctx, l.Addr().String(), opts)
	if err != nil {
		if !strings.Contains(err.Error(), "line too long") {
			t.Errorf("Erwarteter 'line too long' Fehler während Dial, erhalten: %v", err)
		}
		return
	}

	// Falls Dial erfolgreich war (sollte es nicht), probiere ein Kommando
	_, err = client.Noop(ctx)
	if err == nil {
		t.Error("Erwarteter Fehler wegen Zeilenbegrenzung, aber nil erhalten")
	} else if !strings.Contains(err.Error(), "line too long") && !strings.Contains(err.Error(), "EOF") {
		t.Errorf("Erwarteter 'line too long' oder EOF Fehler, erhalten: %v", err)
	}
}

func TestDialMXInvalid(t *testing.T) {
	ctx := context.Background()
	opts := DefaultOptions()

	// No recipients
	_, _, err := DialMX(ctx, nil, opts)
	if err == nil || !strings.Contains(err.Error(), "no recipients") {
		t.Errorf("Expected 'no recipients' error, got %v", err)
	}

	// Invalid recipient
	_, _, err = DialMX(ctx, []string{"invalid"}, opts)
	if err == nil || !strings.Contains(err.Error(), "invalid recipient") {
		t.Errorf("Expected 'invalid recipient' error, got %v", err)
	}

	// Mixed domains
	_, _, err = DialMX(ctx, []string{"a@example.com", "b@other.com"}, opts)
	if err == nil || !strings.Contains(err.Error(), "same domain") {
		t.Errorf("Expected 'same domain' error, got %v", err)
	}
}

// TestDotStuffing verifies that lines starting with "." are properly escaped
// This is critical for DKIM signatures to remain valid during transmission
func TestDotStuffing(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Channel to capture the received DATA
	receivedData := make(chan string, 1)

	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		// Send greeting
		c.Write([]byte("220 test.example.com ESMTP\r\n"))

		buf := make([]byte, 4096)

		// EHLO
		n, _ := c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "EHLO") {
			c.Write([]byte("250-test.example.com\r\n250 8BITMIME\r\n"))
		}

		// MAIL FROM
		n, _ = c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "MAIL FROM") {
			c.Write([]byte("250 2.1.0 Ok\r\n"))
		}

		// RCPT TO
		n, _ = c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "RCPT TO") {
			c.Write([]byte("250 2.1.5 Ok\r\n"))
		}

		// DATA command
		n, _ = c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "DATA") {
			c.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
		}

		// Read DATA content until we see the terminating ".\r\n"
		var dataBuilder strings.Builder
		for {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			chunk := string(buf[:n])
			dataBuilder.WriteString(chunk)

			// Check if we received the terminating sequence
			if strings.HasSuffix(dataBuilder.String(), "\r\n.\r\n") {
				break
			}
		}

		// Send success response
		c.Write([]byte("250 2.0.0 Ok: queued as ABC123\r\n"))

		// Store received data (without the terminating .\r\n)
		data := dataBuilder.String()
		data = strings.TrimSuffix(data, "\r\n.\r\n")
		receivedData <- data

		// QUIT
		n, _ = c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "QUIT") {
			c.Write([]byte("221 2.0.0 Bye\r\n"))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _, err := Dial(ctx, l.Addr().String(), DefaultOptions())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	if _, err := client.Hello(ctx, "client.example.com"); err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	if _, err := client.Mail(ctx, "sender@example.com", nil); err != nil {
		t.Fatalf("Mail failed: %v", err)
	}

	if _, err := client.Rcpt(ctx, "recipient@example.com", nil); err != nil {
		t.Fatalf("Rcpt failed: %v", err)
	}

	w, _, err := client.Data(ctx)
	if err != nil {
		t.Fatalf("Data failed: %v", err)
	}

	// Write a message with lines starting with "."
	// This simulates the real-world case where URLs like ".com/path" appear
	testMessage := "Subject: Test dot-stuffing\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; test=value\r\n" +
		"\r\n" +
		"This line is normal\r\n" +
		".com/deutschland - this line starts with a dot\r\n" +
		"Another normal line\r\n" +
		".\r\n" + // Single dot on a line (should NOT terminate DATA)
		"Line after single dot\r\n"

	if _, err := io.WriteString(w, testMessage); err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if _, err := client.Quit(ctx); err != nil {
		t.Fatalf("Quit failed: %v", err)
	}

	// Verify the received data
	select {
	case data := <-receivedData:
		// Check that lines starting with "." are doubled
		if !strings.Contains(data, "..com/deutschland") {
			t.Errorf("Expected line starting with '.com' to be dot-stuffed to '..com', but got:\n%s", data)
		}

		// Check that single "." line is doubled
		if !strings.Contains(data, "\r\n..\r\n") {
			t.Errorf("Expected single '.' line to be dot-stuffed to '..', but got:\n%s", data)
		}

		// Verify the entire message was received including the line after the single dot
		if !strings.Contains(data, "Line after single dot") {
			t.Errorf("Message was truncated, expected 'Line after single dot' but got:\n%s", data)
		}

		// Verify DKIM signature line is intact
		if !strings.Contains(data, "DKIM-Signature: v=1; a=rsa-sha256; test=value") {
			t.Errorf("DKIM signature line was corrupted, got:\n%s", data)
		}

	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for received data")
	}
}
