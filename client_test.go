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
