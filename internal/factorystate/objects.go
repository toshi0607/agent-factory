package factorystate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	maxObjectBytes = 64 << 10
	readAttempts   = 4
)

type tokenProvider interface {
	Token(context.Context) (string, error)
}

// objects is a minimal Cloud Storage JSON API client for one bucket.
type objects struct {
	google *googleHTTP
	tokens tokenProvider
	bucket string
}

func (o *objects) objectURL(name string) string {
	return storageBase + "/storage/v1/b/" + url.PathEscape(o.bucket) + "/o/" + url.PathEscape(name)
}

func (o *objects) send(ctx context.Context, method, target string, body []byte, operation string) (*http.Response, error) {
	token, err := o.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, errors.New(operation + ": could not construct the request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return o.google.do(req, operation)
}

// retry repeats an idempotent request on transport errors, 429, and 5xx.
func (o *objects) retry(ctx context.Context, attempt func(context.Context) error) error {
	var err error
	for i := range readAttempts {
		if i > 0 {
			if sleepErr := o.google.sleep(ctx, time.Second<<(i-1)); sleepErr != nil {
				return errors.Join(err, sleepErr)
			}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, o.google.timeout)
		err = attempt(attemptCtx)
		cancel()
		if err == nil || !retryable(err) || ctx.Err() != nil {
			return err
		}
	}
	return err
}

// Get reads an object and its generation; a missing object is not an error.
func (o *objects) Get(ctx context.Context, name string) ([]byte, int64, bool, error) {
	operation := "read " + name
	var data []byte
	var generation int64
	var found bool
	err := o.retry(ctx, func(ctx context.Context) error {
		data, generation, found = nil, 0, false
		resp, err := o.send(ctx, http.MethodGet, o.objectURL(name)+"?alt=media", nil, operation)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return nil
		case resp.StatusCode != http.StatusOK:
			return responseError(resp, operation)
		}
		generation, err = strconv.ParseInt(resp.Header.Get("x-goog-generation"), 10, 64)
		if err != nil || generation <= 0 {
			return errors.New(operation + ": response has no valid object generation")
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, maxObjectBytes+1))
		if err != nil {
			return fmt.Errorf("%s: %w", operation, errTransport)
		}
		if len(data) > maxObjectBytes {
			return fmt.Errorf("%s: object exceeds %d bytes", operation, maxObjectBytes)
		}
		found = true
		return nil
	})
	if err != nil {
		return nil, 0, false, err
	}
	return data, generation, found, nil
}

// upload writes an object once with ifGenerationMatch. It reports whether
// the precondition failed and whether a failure leaves the outcome unknown.
func (o *objects) upload(ctx context.Context, name string, data []byte, ifGeneration int64) (preconditionFailed, ambiguous bool, err error) {
	operation := "write " + name
	if len(data) > maxObjectBytes {
		return false, false, fmt.Errorf("%s: object exceeds %d bytes", operation, maxObjectBytes)
	}
	query := url.Values{
		"uploadType":        {"media"},
		"name":              {name},
		"ifGenerationMatch": {strconv.FormatInt(ifGeneration, 10)},
	}
	target := storageBase + "/upload/storage/v1/b/" + url.PathEscape(o.bucket) + "/o?" + query.Encode()
	ctx, cancel := context.WithTimeout(ctx, o.google.timeout)
	defer cancel()
	resp, err := o.send(ctx, http.MethodPost, target, data, operation)
	if err != nil {
		return false, errors.Is(err, errTransport), err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
		return false, false, nil
	case resp.StatusCode == http.StatusPreconditionFailed:
		return true, false, nil
	default:
		return false, resp.StatusCode >= 500, responseError(resp, operation)
	}
}

// resolve learns the outcome of an ambiguous upload with one read.
func (o *objects) resolve(ctx context.Context, name string, data []byte, uploadErr error) (written, exists bool, err error) {
	got, _, found, getErr := o.Get(ctx, name)
	if getErr != nil {
		return false, false, errors.Join(uploadErr, getErr)
	}
	return found && bytes.Equal(got, data), found, nil
}

// Create writes an object only if it does not exist yet.
func (o *objects) Create(ctx context.Context, name string, data []byte) (bool, error) {
	exists, ambiguous, err := o.upload(ctx, name, data, 0)
	switch {
	case err == nil:
		return !exists, nil
	case !ambiguous:
		return false, err
	}
	written, found, resolveErr := o.resolve(ctx, name, data, err)
	if resolveErr != nil {
		return false, resolveErr
	}
	if !found {
		return false, err
	}
	return written, nil
}

// Replace overwrites an object only if its generation still matches.
func (o *objects) Replace(ctx context.Context, name string, data []byte, generation int64) error {
	if generation <= 0 {
		return errors.New("replace " + name + ": a positive generation is required")
	}
	changed, ambiguous, err := o.upload(ctx, name, data, generation)
	switch {
	case changed:
		return errors.New("replace " + name + ": object changed since it was read")
	case err == nil:
		return nil
	case !ambiguous:
		return err
	}
	written, _, resolveErr := o.resolve(ctx, name, data, err)
	if resolveErr != nil {
		return resolveErr
	}
	if !written {
		return err
	}
	return nil
}

// Delete removes an object only if its generation still matches; a missing
// object counts as deleted.
func (o *objects) Delete(ctx context.Context, name string, generation int64) error {
	operation := "delete " + name
	if generation <= 0 {
		return errors.New(operation + ": a positive generation is required")
	}
	target := o.objectURL(name) + "?ifGenerationMatch=" + strconv.FormatInt(generation, 10)
	return o.retry(ctx, func(ctx context.Context) error {
		resp, err := o.send(ctx, http.MethodDelete, target, nil, operation)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
			return nil
		case http.StatusPreconditionFailed:
			return errors.New(operation + ": object changed since it was read")
		default:
			return responseError(resp, operation)
		}
	})
}
