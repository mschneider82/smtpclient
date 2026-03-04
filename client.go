package smtpclient

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
)

// DefaultLocalName is the default local name used in HELO/EHLO.
var DefaultLocalName = "localhost"

// A Client represents a client connection to an SMTP server.
type Client struct {
	conn       net.Conn
	text       *textproto.Conn
	serverName string
	lmtp       bool
	ext        map[string]string // supported extensions
	localName  string            // the name to use in HELO/EHLO/LHLO
	didGreet   bool              // whether we've received greeting from server
	greetError error             // the error from the greeting
	didHello   bool              // whether we've said HELO/EHLO/LHLO
	helloError error             // the error from the hello
	rcpts      []string          // recipients accumulated for the current session

	isClosed bool

	// LineLimit is the maximum line length. Defaults to 2000.
	LineLimit int

	opts Options

	// Logger for all network activity.
	DebugWriter io.Writer
}

// Dial returns a new Client connected to an SMTP server at addr.
func Dial(ctx context.Context, addr string, opts Options) (*Client, Response, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, Response{}, err
	}
	host, _, _ := net.SplitHostPort(addr)
	c, resp, err := NewClient(ctx, conn, opts)
	if err != nil {
		return nil, resp, err
	}
	c.serverName = host
	return c, resp, nil
}

// DialMX returns a new Client connected to an SMTP server for the given recipients' domain.
// It performs an MX lookup and tries to connect to the servers in order of preference.
// All recipients must belong to the same domain.
func DialMX(ctx context.Context, rcpts []string, opts Options) (*Client, Response, error) {
	if len(rcpts) == 0 {
		return nil, Response{}, errors.New("smtpclient: no recipients provided")
	}

	// Extract domain from the first recipient
	first := rcpts[0]
	idx := strings.LastIndex(first, "@")
	if idx == -1 {
		return nil, Response{}, fmt.Errorf("smtpclient: invalid recipient address: %s", first)
	}
	domain := first[idx+1:]

	// Verify all recipients are in the same domain
	for _, rcpt := range rcpts[1:] {
		idx := strings.LastIndex(rcpt, "@")
		if idx == -1 || rcpt[idx+1:] != domain {
			return nil, Response{}, errors.New("smtpclient: all recipients must belong to the same domain")
		}
	}

	mxs, err := net.LookupMX(domain)
	if err != nil {
		// Fallback to A record if MX lookup fails or returns no records
		return Dial(ctx, domain+":25", opts)
	}

	var lastErr error
	for _, mx := range mxs {
		c, resp, err := Dial(ctx, net.JoinHostPort(mx.Host, "25"), opts)
		if err == nil {
			return c, resp, nil
		}
		lastErr = err
	}

	return nil, Response{}, fmt.Errorf("smtpclient: failed to connect to any MX server for %s: %v", domain, lastErr)
}

// DialTLS returns a new Client connected to an SMTP server via TLS at addr.
func DialTLS(ctx context.Context, addr string, tlsConfig *tls.Config, opts Options) (*Client, Response, error) {
	var d tls.Dialer
	d.Config = tlsConfig
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, Response{}, err
	}
	host, _, _ := net.SplitHostPort(addr)
	c, resp, err := NewClient(ctx, conn, opts)
	if err != nil {
		return nil, resp, err
	}
	c.serverName = host
	return c, resp, nil
}

// StartTLS sends the STARTTLS command and upgrades the connection to TLS.
func (c *Client) StartTLS(ctx context.Context, config *tls.Config) (Response, error) {
	resp, err := c.cmd(ctx, 220, "STARTTLS")
	if err != nil {
		return resp, err
	}
	tlsConn := tls.Client(c.conn, config)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		c.Close()
		return resp, err
	}

	c.setConn(tlsConn)
	return resp, nil
}

// NewClient returns a new Client using an existing connection and host as a server name to be used when authenticating.
func NewClient(ctx context.Context, conn net.Conn, opts Options) (*Client, Response, error) {
	if opts.LocalName == "" {
		opts.LocalName = DefaultLocalName
	}
	if opts.CommandTimeout == 0 {
		opts.CommandTimeout = 5 * time.Minute
	}
	if opts.SubmissionTimeout == 0 {
		opts.SubmissionTimeout = 12 * time.Minute
	}
	if opts.LineLimit <= 0 {
		opts.LineLimit = 2000
	}

	c := &Client{
		conn:      conn,
		opts:      opts,
		LineLimit: opts.LineLimit,
	}
	c.setConn(conn)

	resp, err := c.readResponse(ctx, 220)
	if err != nil {
		return nil, resp, err
	}
	c.didGreet = true
	return c, resp, nil
}

// NewClientLMTP returns a new LMTP Client (as defined in RFC 2033) using an
// existing connection and host as a server name to be used when authenticating.
func NewClientLMTP(ctx context.Context, conn net.Conn, opts Options) (*Client, Response, error) {
	c, resp, err := NewClient(ctx, conn, opts)
	if err != nil {
		return nil, resp, err
	}
	c.lmtp = true
	return c, resp, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	if c.isClosed {
		return nil
	}
	c.isClosed = true
	return c.text.Close()
}

func (c *Client) setConn(conn net.Conn) {
	c.conn = conn

	limit := c.LineLimit
	if limit <= 0 {
		limit = 2000
	}

	r := &lineLimitReader{
		R:         conn,
		LineLimit: limit,
	}

	c.text = textproto.NewConn(struct {
		io.Reader
		io.Writer
		io.Closer
	}{
		Reader: io.TeeReader(r, clientDebugWriter{c}),
		Writer: io.MultiWriter(conn, clientDebugWriter{c}),
		Closer: conn,
	})
}

type lineLimitReader struct {
	R         io.Reader
	LineLimit int
	lineLen   int
}

func (r *lineLimitReader) Read(b []byte) (int, error) {
	n, err := r.R.Read(b)
	if n > 0 {
		for i := 0; i < n; i++ {
			c := b[i]
			if c == '\n' {
				r.lineLen = 0
			} else if c != '\r' {
				r.lineLen++
			}
			if r.lineLen > r.LineLimit {
				return i + 1, errors.New("smtpclient: line too long")
			}
		}
	}
	return n, err
}

type clientDebugWriter struct {
	c *Client
}

func (cdw clientDebugWriter) Write(b []byte) (int, error) {
	if cdw.c.DebugWriter == nil {
		return len(b), nil
	}
	return cdw.c.DebugWriter.Write(b)
}

func (c *Client) readResponse(ctx context.Context, expectCode int) (Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if deadline, ok := ctx.Deadline(); ok {
		c.conn.SetReadDeadline(deadline)
		defer c.conn.SetReadDeadline(time.Time{})
	}

	code, msg, err := c.text.ReadResponse(expectCode)
	if err != nil {
		var protoErr *textproto.Error
		if errors.As(err, &protoErr) {
			smtpErr := toSMTPErr(protoErr)
			return Response{smtpErr.Code, smtpErr.EnhancedCode, smtpErr.Message}, smtpErr
		}
		return Response{}, err
	}

	resp := Response{Code: code}
	parts := strings.SplitN(msg, " ", 2)
	if len(parts) == 2 {
		if enchCode, err := parseEnhancedCode(parts[0]); err == nil {
			resp.EnhancedCode = enchCode
			resp.Message = parts[1]
			// Per RFC 2034, enhanced code should be prepended to each line.
			resp.Message = strings.ReplaceAll(resp.Message, "\n"+parts[0]+" ", "\n")
		} else {
			resp.Message = msg
			resp.EnhancedCode = EnhancedCodeNotSet
		}
	} else {
		resp.Message = msg
		resp.EnhancedCode = EnhancedCodeNotSet
	}

	return resp, nil
}

func (c *Client) cmd(ctx context.Context, expectCode int, format string, args ...interface{}) (Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if deadline, ok := ctx.Deadline(); ok {
		c.conn.SetWriteDeadline(deadline)
		defer c.conn.SetWriteDeadline(time.Time{})
	}

	id, err := c.text.Cmd(format, args...)
	if err != nil {
		return Response{}, err
	}
	c.text.StartResponse(id)
	defer c.text.EndResponse(id)

	return c.readResponse(ctx, expectCode)
}

// Hello sends the HELO or EHLO command to the server.
// If the server supports EHLO, it will be used. Otherwise, it falls back to HELO.
func (c *Client) Hello(ctx context.Context, localName string) (Response, error) {
	if localName != "" {
		c.localName = localName
	} else {
		c.localName = c.opts.LocalName
	}

	if c.lmtp {
		return c.lhlo(ctx)
	}

	resp, err := c.ehlo(ctx)
	if err != nil {
		// Try HELO if EHLO fails? Traditional smtp does that.
		return c.helo(ctx)
	}
	return resp, nil
}

func (c *Client) ehlo(ctx context.Context) (Response, error) {
	resp, err := c.cmd(ctx, 250, "EHLO %s", c.localName)
	if err != nil {
		return resp, err
	}

	c.ext = make(map[string]string)
	lines := strings.Split(resp.Message, "\n")
	if len(lines) > 0 {
		for _, line := range lines {
			args := strings.SplitN(line, " ", 2)
			if len(args) > 1 {
				c.ext[strings.ToUpper(args[0])] = args[1]
			} else {
				c.ext[strings.ToUpper(args[0])] = ""
			}
		}
	}
	c.didHello = true
	c.rcpts = nil
	return resp, nil
}

func (c *Client) helo(ctx context.Context) (Response, error) {
	resp, err := c.cmd(ctx, 250, "HELO %s", c.localName)
	if err != nil {
		return resp, err
	}
	c.ext = nil
	c.didHello = true
	c.rcpts = nil
	return resp, nil
}

func (c *Client) lhlo(ctx context.Context) (Response, error) {
	resp, err := c.cmd(ctx, 250, "LHLO %s", c.localName)
	if err != nil {
		return resp, err
	}
	// Similar to EHLO
	c.ext = make(map[string]string)
	lines := strings.Split(resp.Message, "\n")
	for _, line := range lines {
		args := strings.SplitN(line, " ", 2)
		if len(args) > 1 {
			c.ext[strings.ToUpper(args[0])] = args[1]
		} else {
			c.ext[strings.ToUpper(args[0])] = ""
		}
	}
	c.didHello = true
	c.rcpts = nil
	return resp, nil
}

// Mail sends the MAIL FROM command to the server with the provided sender and options.
func (c *Client) Mail(ctx context.Context, from string, opts *MailOptions) (Response, error) {
	c.rcpts = nil
	cmd := "MAIL FROM:<" + from + ">"
	if opts != nil {
		if opts.Size > 0 {
			cmd += fmt.Sprintf(" SIZE=%d", opts.Size)
		}
		if opts.UTF8 {
			cmd += " SMTPUTF8"
		}
		if opts.Body != "" {
			cmd += " BODY=" + string(opts.Body)
		}
		if opts.Return != "" {
			cmd += " RET=" + string(opts.Return)
		}
		if opts.EnvelopeID != "" {
			cmd += " ENVID=" + opts.EnvelopeID
		}
		if opts.Auth != nil {
			if *opts.Auth == "" {
				cmd += " AUTH=<>"
			} else {
				cmd += " AUTH=<" + *opts.Auth + ">"
			}
		}
		if opts.RequireTLS {
			cmd += " REQUIRETLS"
		}
	}
	return c.cmd(ctx, 250, "%s", cmd)
}

// Rcpt sends the RCPT TO command to the server with the provided recipient and options.
func (c *Client) Rcpt(ctx context.Context, to string, opts *RcptOptions) (Response, error) {
	cmd := "RCPT TO:<" + to + ">"
	if opts != nil {
		if len(opts.Notify) > 0 {
			parts := make([]string, len(opts.Notify))
			for i, n := range opts.Notify {
				parts[i] = string(n)
			}
			cmd += " NOTIFY=" + strings.Join(parts, ",")
		}
		if opts.OriginalRecipient != "" {
			cmd += " ORCPT=" + string(opts.OriginalRecipientType) + ";" + opts.OriginalRecipient
		}
		if !opts.RequireRecipientValidSince.IsZero() {
			cmd += " RRVS=" + opts.RequireRecipientValidSince.Format(time.RFC3339)
		}
		if opts.DeliverBy != nil {
			cmd += fmt.Sprintf(" BY=%d;%s", int(opts.DeliverBy.Time.Seconds()), opts.DeliverBy.Mode)
			if opts.DeliverBy.Trace {
				cmd += "T"
			}
		}
		if opts.MTPriority != nil {
			cmd += fmt.Sprintf(" MT-PRIORITY=%d", *opts.MTPriority)
		}
	}
	resp, err := c.cmd(ctx, 250, "%s", cmd)
	if err == nil {
		c.rcpts = append(c.rcpts, to)
	}
	return resp, err
}

// DataCommand is a pending DATA command. DataCommand is an io.WriteCloser.
// See Client.Data.
type DataCommand struct {
	client    *Client
	ctx       context.Context
	dotWriter io.WriteCloser
}

// Write implements io.Writer.
func (cmd *DataCommand) Write(p []byte) (n int, err error) {
	if deadline, ok := cmd.ctx.Deadline(); ok {
		cmd.client.conn.SetWriteDeadline(deadline)
		defer cmd.client.conn.SetWriteDeadline(time.Time{})
	}
	return cmd.dotWriter.Write(p)
}

// Close implements io.Closer.
func (cmd *DataCommand) Close() error {
	var err error
	if cmd.client.lmtp {
		_, err = cmd.CloseWithLMTPResponse()
	} else {
		_, err = cmd.CloseWithResponse()
	}
	return err
}

// CloseWithResponse is equivalent to Close, but also returns the server response.
// It cannot be called when the LMTP protocol is used.
func (cmd *DataCommand) CloseWithResponse() (*DataResponse, error) {
	if cmd.client.lmtp {
		return nil, errors.New("smtpclient: CloseWithResponse used with an LMTP client")
	}

	if deadline, ok := cmd.ctx.Deadline(); ok {
		cmd.client.conn.SetWriteDeadline(deadline)
		defer cmd.client.conn.SetWriteDeadline(time.Time{})
	}

	// Close the dot writer (sends the terminating .\r\n)
	if err := cmd.dotWriter.Close(); err != nil {
		return nil, err
	}

	resp, err := cmd.client.readResponse(cmd.ctx, 250)
	if err != nil {
		return nil, err
	}
	return &DataResponse{StatusText: resp.Message}, nil
}

// CloseWithLMTPResponse is equivalent to Close, but also returns per-recipient server responses.
// It can only be called when the LMTP protocol is used.
func (cmd *DataCommand) CloseWithLMTPResponse() (map[string]*DataResponse, error) {
	if !cmd.client.lmtp {
		return nil, errors.New("smtpclient: CloseWithLMTPResponse used without an LMTP client")
	}

	if deadline, ok := cmd.ctx.Deadline(); ok {
		cmd.client.conn.SetWriteDeadline(deadline)
		defer cmd.client.conn.SetWriteDeadline(time.Time{})
	}

	// Close the dot writer (sends the terminating .\r\n)
	if err := cmd.dotWriter.Close(); err != nil {
		return nil, err
	}

	resp := make(map[string]*DataResponse, len(cmd.client.rcpts))
	lmtpErr := make(LMTPDataError, len(cmd.client.rcpts))
	for i := 0; i < len(cmd.client.rcpts); i++ {
		rcpt := cmd.client.rcpts[i]
		r, err := cmd.client.readResponse(cmd.ctx, 250)
		if err != nil {
			var smtpErr *SMTPError
			if errors.As(err, &smtpErr) {
				lmtpErr[rcpt] = smtpErr
			} else {
				if len(lmtpErr) > 0 {
					return resp, errors.Join(err, lmtpErr)
				}
				return resp, err
			}
		} else {
			resp[rcpt] = &DataResponse{StatusText: r.Message}
		}
	}

	if len(lmtpErr) > 0 {
		return resp, lmtpErr
	}
	return resp, nil
}

// Data sends the DATA command and returns a writer for the message body.
func (c *Client) Data(ctx context.Context) (*DataCommand, Response, error) {
	resp, err := c.cmd(ctx, 354, "DATA")
	if err != nil {
		return nil, resp, err
	}
	// Create a dot writer for proper SMTP DATA encoding (dot-stuffing)
	dotWriter := c.text.DotWriter()
	return &DataCommand{client: c, ctx: ctx, dotWriter: dotWriter}, resp, nil
}

// Auth authenticates the client using the provided SASL client.
func (c *Client) Auth(ctx context.Context, a sasl.Client) (Response, error) {
	mech, ir, err := a.Start()
	if err != nil {
		return Response{}, err
	}

	cmd := "AUTH " + mech
	if ir != nil {
		cmd += " " + base64.StdEncoding.EncodeToString(ir)
	}

	resp, err := c.cmd(ctx, 0, "%s", cmd)
	for err == nil && resp.Code == 334 {
		var challenge []byte
		challenge, err = base64.StdEncoding.DecodeString(resp.Message)
		if err != nil {
			return resp, err
		}

		var response []byte
		response, err = a.Next(challenge)
		if err != nil {
			return resp, err
		}

		resp, err = c.cmd(ctx, 0, "%s", base64.StdEncoding.EncodeToString(response))
	}

	if err != nil {
		return resp, err
	}
	if resp.Code != 235 {
		return resp, &SMTPError{Code: resp.Code, EnhancedCode: resp.EnhancedCode, Message: resp.Message}
	}

	return resp, nil
}

// Reset sends the RSET command to the server, aborting the current mail transaction.
func (c *Client) Reset(ctx context.Context) (Response, error) {
	resp, err := c.cmd(ctx, 250, "RSET")
	if err == nil {
		c.rcpts = nil
	}
	return resp, err
}

// Noop sends the NOOP command to the server, which does nothing but check the connection.
func (c *Client) Noop(ctx context.Context) (Response, error) {
	return c.cmd(ctx, 250, "NOOP")
}

// Quit sends the QUIT command and closes the connection to the server.
func (c *Client) Quit(ctx context.Context) (Response, error) {
	resp, err := c.cmd(ctx, 221, "QUIT")
	if err != nil {
		return resp, err
	}
	return resp, c.Close()
}

// Extension returns whether the server supports the provided extension.
func (c *Client) Extension(ext string) (bool, string) {
	if c.ext == nil {
		return false, ""
	}
	val, ok := c.ext[strings.ToUpper(ext)]
	return ok, val
}

// SupportsAuth checks whether an authentication mechanism is supported.
func (c *Client) SupportsAuth(mech string) bool {
	mechs, ok := c.ext["AUTH"]
	if !ok {
		return false
	}
	for _, m := range strings.Split(mechs, " ") {
		if strings.EqualFold(m, mech) {
			return true
		}
	}
	return false
}

// MaxMessageSize returns the maximum message size accepted by the server.
// 0 means unlimited.
//
// If the server doesn't convey this information, ok = false is returned.
func (c *Client) MaxMessageSize() (size int, ok bool) {
	v := c.ext["SIZE"]
	if v == "" {
		return 0, false
	}
	size, err := strconv.Atoi(v)
	if err != nil || size < 0 {
		return 0, false
	}
	return size, true
}

// TLSConnectionState returns the client's TLS connection state.
// The return values are their zero values if STARTTLS did
// not succeed.
func (c *Client) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	tc, ok := c.conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

// LocalAddr returns the local network address.
func (c *Client) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Client) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// Verify checks the validity of an email address on the server.
// If Verify returns nil, the address is valid. A non-nil return
// does not necessarily indicate an invalid address. Many servers
// will not verify addresses for security reasons.
//
// If server returns an error, it will be of type *SMTPError.
func (c *Client) Verify(ctx context.Context, addr string) (Response, error) {
	return c.cmd(ctx, 250, "VRFY %s", addr)
}

func parseEnhancedCode(s string) (EnhancedCode, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return EnhancedCode{}, fmt.Errorf("wrong amount of enhanced code parts")
	}

	code := EnhancedCode{}
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return code, err
		}
		code[i] = num
	}
	return code, nil
}

func toSMTPErr(protoErr *textproto.Error) *SMTPError {
	smtpErr := &SMTPError{
		Code:    protoErr.Code,
		Message: protoErr.Msg,
	}

	parts := strings.SplitN(protoErr.Msg, " ", 2)
	if len(parts) != 2 {
		return smtpErr
	}

	enchCode, err := parseEnhancedCode(parts[0])
	if err != nil {
		return smtpErr
	}

	msg := parts[1]
	msg = strings.ReplaceAll(msg, "\n"+parts[0]+" ", "\n")

	smtpErr.EnhancedCode = enchCode
	smtpErr.Message = msg
	return smtpErr
}

// SendMail connects to the server at addr, switches to TLS if possible,
// authenticates with mechanism a if provided, and sends an email from
// address from, to addresses to, with message body r.
func SendMail(ctx context.Context, addr string, a sasl.Client, from string, to []string, r io.Reader, opts Options) (Response, error) {
	c, resp, err := Dial(ctx, addr, opts)
	if err != nil {
		return resp, err
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: c.serverName}
		if _, err := c.StartTLS(ctx, config); err != nil {
			return resp, err
		}
	}

	if a != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if _, err := c.Auth(ctx, a); err != nil {
				return resp, err
			}
		} else {
			return resp, errors.New("smtpclient: server doesn't support AUTH")
		}
	}

	if resp, err = c.Hello(ctx, ""); err != nil {
		return resp, err
	}

	if resp, err = c.Mail(ctx, from, nil); err != nil {
		return resp, err
	}

	for _, addr := range to {
		if resp, err = c.Rcpt(ctx, addr, nil); err != nil {
			return resp, err
		}
	}

	w, resp, err := c.Data(ctx)
	if err != nil {
		return resp, err
	}
	_, err = io.Copy(w, r)
	if err != nil {
		w.Close()
		return resp, err
	}
	err = w.Close()
	return resp, err
}
