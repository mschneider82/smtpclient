package smtpclient

import (
	"fmt"
	"strings"
	"time"
)

// Response represents an SMTP server response.
type Response struct {
	Code         int
	EnhancedCode EnhancedCode
	Message      string
}

func (r Response) String() string {
	if r.EnhancedCode == NoEnhancedCode {
		return fmt.Sprintf("%d %s", r.Code, r.Message)
	}
	return fmt.Sprintf("%d %d.%d.%d %s", r.Code, r.EnhancedCode[0], r.EnhancedCode[1], r.EnhancedCode[2], r.Message)
}

// EnhancedCode represents an ESMTP enhanced status code.
type EnhancedCode [3]int

// NoEnhancedCode is used to indicate that enhanced error code should not be
// included in response.
var NoEnhancedCode = EnhancedCode{-1, -1, -1}

// EnhancedCodeNotSet is used to indicate that backend failed to provide
// enhanced status code. X.0.0 will be used (X is derived from error code).
var EnhancedCodeNotSet = EnhancedCode{0, 0, 0}

// SMTPError represents an SMTP error.
type SMTPError struct {
	Code         int
	EnhancedCode EnhancedCode
	Message      string
}

func (err *SMTPError) Error() string {
	return (&Response{err.Code, err.EnhancedCode, err.Message}).String()
}

// Options contains client options.
type Options struct {
	// LocalName is the name used in HELO/EHLO. Defaults to DefaultLocalName.
	LocalName string

	// CommandTimeout is the time to wait for command responses.
	CommandTimeout time.Duration
	// SubmissionTimeout is the time to wait for responses after final dot in DATA.
	SubmissionTimeout time.Duration

	// LineLimit is the maximum line length. Defaults to 2000.
	LineLimit int
}

func DefaultOptions() Options {
	return Options{
		LocalName:         "localhost",
		CommandTimeout:    5 * time.Minute,
		SubmissionTimeout: 12 * time.Minute,
		LineLimit:         2000,
	}
}

type BodyType string

const (
	Body7Bit       BodyType = "7BIT"
	Body8BitMIME   BodyType = "8BITMIME"
	BodyBinaryMIME BodyType = "BINARYMIME"
)

type DSNReturn string

const (
	DSNReturnFull    DSNReturn = "FULL"
	DSNReturnHeaders DSNReturn = "HDRS"
)

// MailOptions contains parameters for the MAIL command.
type MailOptions struct {
	Body       BodyType
	Size       int64
	RequireTLS bool
	UTF8       bool
	Return     DSNReturn
	EnvelopeID string
	Auth       *string
}

type DSNNotify string

const (
	DSNNotifyNever   DSNNotify = "NEVER"
	DSNNotifyDelayed DSNNotify = "DELAY"
	DSNNotifyFailure DSNNotify = "FAILURE"
	DSNNotifySuccess DSNNotify = "SUCCESS"
)

type DSNAddressType string

const (
	DSNAddressTypeRFC822 DSNAddressType = "RFC822"
	DSNAddressTypeUTF8   DSNAddressType = "UTF-8"
)

type DeliverByMode string

const (
	DeliverByNotify DeliverByMode = "N"
	DeliverByReturn DeliverByMode = "R"
)

type DeliverByOptions struct {
	Time  time.Duration
	Mode  DeliverByMode
	Trace bool
}

// RcptOptions contains parameters for the RCPT command.
type RcptOptions struct {
	Notify                     []DSNNotify
	OriginalRecipientType      DSNAddressType
	OriginalRecipient          string
	RequireRecipientValidSince time.Time
	DeliverBy                  *DeliverByOptions
	MTPriority                 *int
}

// DataResponse is the response returned by a DATA command.
type DataResponse struct {
	// StatusText is the status text returned by the server. It may contain
	// tracking information.
	StatusText string
}

// LMTPDataError is a collection of errors returned by an LMTP server for a
// DATA command. It holds per-recipient errors.
type LMTPDataError map[string]*SMTPError

// Error implements error.
func (lmtpErr LMTPDataError) Error() string {
	l := lmtpErr.Unwrap()
	errs := make([]string, 0, len(l))
	for _, err := range l {
		errs = append(errs, err.Error())
	}
	return strings.Join(errs, "; ")
}

// Unwrap returns all per-recipient errors returned by the server.
func (lmtpErr LMTPDataError) Unwrap() []error {
	l := make([]error, 0, len(lmtpErr))
	for rcpt, smtpErr := range lmtpErr {
		l = append(l, fmt.Errorf("<%v>: %w", rcpt, smtpErr))
	}
	return l
}
