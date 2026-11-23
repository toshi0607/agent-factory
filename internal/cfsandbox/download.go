package cfsandbox

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
)

// Output reports whether the saved output was truncated.
func (c *Client) Output(ctx context.Context, id, name string, w io.Writer, maxBytes int64) (bool, error) {
	if !fileName.MatchString(name) {
		return false, errors.New("invalid worker output name")
	}
	keepTruncated := name == "events.jsonl" || name == "stderr.log" || name == "probe.txt"
	var workerTruncated bool
	truncated, err := c.download(ctx, id, "/outputs/"+name, w, maxBytes, keepTruncated, func(header http.Header) error {
		workerTruncated = header.Get("X-Factory-Truncated") != ""
		if workerTruncated && !keepTruncated {
			return errors.New("worker returned a truncated output")
		}
		return nil
	})
	return err == nil && (truncated || workerTruncated), err
}

func (c *Client) Egress(ctx context.Context, id string, w io.Writer, maxBytes int64) (int, error) {
	var dropped int
	_, err := c.download(ctx, id, "/egress", w, maxBytes, false, func(header http.Header) error {
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
func (c *Client) download(ctx context.Context, id, resource string, w io.Writer, maxBytes int64, keepTruncated bool, checkHeader func(http.Header) error) (bool, error) {
	req, err := c.newRequest(ctx, http.MethodGet, id, resource, nil)
	if err != nil {
		return false, err
	}
	var staging *os.File
	defer func() {
		if staging != nil {
			staging.Close()
			os.Remove(staging.Name())
		}
	}()
	err = c.send(req, http.StatusOK, 5, downloadTimeout, func(resp *http.Response) error {
		if checkHeader != nil {
			if err := checkHeader(resp.Header); err != nil {
				return err
			}
		}
		if !keepTruncated && maxBytes >= 0 && resp.ContentLength > maxBytes {
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
	truncated := keepTruncated && errors.Is(err, errOutputLimit)
	if err != nil && !truncated {
		return false, err
	}
	if _, err := staging.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	_, err = io.Copy(w, contextReader{ctx, staging})
	return truncated, err
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
