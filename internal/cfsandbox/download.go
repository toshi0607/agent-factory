package cfsandbox

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
)

func (c *Client) Output(ctx context.Context, id, name string, w io.Writer, maxBytes int64) error {
	if !fileName.MatchString(name) {
		return errors.New("invalid worker output name")
	}
	return c.download(ctx, id, "/outputs/"+name, w, maxBytes, nil)
}

func (c *Client) Egress(ctx context.Context, id string, w io.Writer, maxBytes int64) (int, error) {
	var dropped int
	err := c.download(ctx, id, "/egress", w, maxBytes, func(header http.Header) error {
		var err error
		dropped, err = strconv.Atoi(header.Get("X-Egress-Dropped"))
		if err != nil || dropped < 0 {
			return errors.New("invalid worker egress dropped count")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return dropped, nil
}

// Stage the response so a failed or retried download never writes a partial body to w.
func (c *Client) download(ctx context.Context, id, resource string, w io.Writer, maxBytes int64, checkHeader func(http.Header) error) error {
	req, err := c.newRequest(ctx, http.MethodGet, id, resource, nil)
	if err != nil {
		return err
	}
	var staging *os.File
	defer func() {
		if staging != nil {
			staging.Close()
			os.Remove(staging.Name())
		}
	}()
	err = c.send(req, http.StatusOK, 5, fileTimeout, func(resp *http.Response) error {
		if checkHeader != nil {
			if err := checkHeader(resp.Header); err != nil {
				return err
			}
		}
		if maxBytes >= 0 && resp.ContentLength > maxBytes {
			return errOutputLimit
		}
		if staging == nil {
			var err error
			staging, err = os.CreateTemp("", "factory-worker-*")
			if err != nil {
				return err
			}
		} else {
			if err := staging.Truncate(0); err != nil {
				return err
			}
			if _, err := staging.Seek(0, io.SeekStart); err != nil {
				return err
			}
		}
		return copyResponse(staging, resp.Body, maxBytes)
	})
	if err != nil {
		return err
	}
	if _, err := staging.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err = io.Copy(w, contextReader{ctx, staging})
	return err
}

var errOutputLimit = errors.New("worker output exceeds byte limit")

type contextReader struct {
	ctx context.Context
	io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

type responseReader struct{ io.Reader }

func (r responseReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && err != io.EOF {
		err = errReadResponse
	}
	return n, err
}

func copyResponse(w io.Writer, body io.Reader, maxBytes int64) error {
	reader := responseReader{body}
	if maxBytes < 0 {
		_, err := io.Copy(w, reader)
		return err
	}
	n, err := io.Copy(w, io.LimitReader(reader, maxBytes))
	if err != nil || n < maxBytes {
		return err
	}
	var extra [1]byte
	if _, err := io.ReadFull(reader, extra[:]); err != io.EOF {
		if err != nil {
			return err
		}
		return errOutputLimit
	}
	return nil
}
