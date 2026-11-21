package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/internal/policy"
)

const downloadTimeout = 5 * time.Minute

func (p preparer) prepareToolchain(ctx context.Context, out string, goTool policy.Go) error {
	path := filepath.Join(out, goTool.Filename)
	if existing, err := delivery.Inspect(path); err == nil {
		if strings.EqualFold(existing.SHA256, goTool.SHA256) {
			return nil
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	err := p.download(ctx, goTool.URL, path, func(w io.Writer, r io.Reader) error {
		hash := sha256.New()
		n, err := io.Copy(io.MultiWriter(w, hash), r)
		if err != nil {
			return err
		}
		if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), goTool.SHA256) {
			return errors.New("sha256 mismatch")
		}
		if n != goTool.SizeBytes {
			return fmt.Errorf("size mismatch: got %d bytes, expected %d", n, goTool.SizeBytes)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("toolchain %s: %w", goTool.Filename, err)
	}
	return nil
}

func (p preparer) download(ctx context.Context, address, dest string, copyBody func(io.Writer, io.Reader) error) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return errors.New("invalid download URL")
	}
	resp, err := p.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A module zip redirect can contain a signed storage URL.
		return fmt.Errorf("GET %s: download failed", req.URL.EscapedPath())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", req.URL.EscapedPath(), resp.StatusCode)
	}
	return delivery.WriteAtomic(dest, func(w io.Writer) error { return copyBody(w, resp.Body) })
}

func (p preparer) prepareModules(ctx context.Context, out, deps, mainModule string) (bool, error) {
	proxy, err := url.Parse(strings.TrimRight(p.proxyBase, "/"))
	if err != nil || proxy.Hostname() == "" || (proxy.Scheme != "http" && proxy.Scheme != "https") ||
		proxy.User != nil || proxy.RawQuery != "" || proxy.Fragment != "" {
		return false, errors.New("invalid module proxy base URL")
	}
	stage, err := os.MkdirTemp(out, ".modproxy-*")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(stage)

	lines := strings.Split(deps, "\n")
	slices.Sort(lines)
	versions := make(map[string][]string)
	for _, line := range slices.Compact(lines) {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == mainModule || len(fields) == 1 {
			continue
		}
		if len(fields) != 2 {
			return false, fmt.Errorf("invalid Go module listing line: %q", line)
		}
		path, err := escapeModulePart(fields[0])
		if err != nil {
			return false, err
		}
		version, err := escapeModulePart(fields[1])
		if err != nil {
			return false, err
		}
		if strings.Contains(version, "/") {
			return false, fmt.Errorf("invalid Go module version: %q", fields[1])
		}
		prefix := proxy.String() + "/" + path + "/@v/" + version
		redirected, err := p.redirected(ctx, prefix+".zip")
		if err != nil {
			return false, err
		}
		if !redirected {
			continue
		}
		dir := filepath.Join(stage, "modproxy", filepath.FromSlash(path), "@v")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return false, err
		}
		for _, ext := range []string{".info", ".mod", ".zip"} {
			err := p.download(ctx, prefix+ext, filepath.Join(dir, version+ext), func(w io.Writer, r io.Reader) error {
				_, err := io.Copy(w, r)
				return err
			})
			if err != nil {
				return false, err
			}
		}
		versions[dir] = append(versions[dir], fields[1])
	}
	for dir, list := range versions {
		if err := os.WriteFile(filepath.Join(dir, "list"), []byte(strings.Join(list, "\n")+"\n"), 0o644); err != nil {
			return false, err
		}
	}

	archive := filepath.Join(out, "modproxy.tar.gz")
	proxyDir := filepath.Join(out, "modproxy")
	if err := os.RemoveAll(proxyDir); err != nil {
		return false, err
	}
	if len(versions) == 0 {
		return false, removeIfPresent(archive)
	}
	if err := delivery.WriteAtomic(archive, func(w io.Writer) error { return archiveProxy(w, stage) }); err != nil {
		return false, err
	}
	return true, os.Rename(filepath.Join(stage, "modproxy"), proxyDir)
}

func escapeModulePart(part string) (string, error) {
	for segment := range strings.SplitSeq(part, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("invalid Go module path or version: %q", part)
		}
	}
	var escaped strings.Builder
	for _, ch := range part {
		switch {
		case ch >= 'A' && ch <= 'Z':
			escaped.WriteByte('!')
			escaped.WriteRune(ch + ('a' - 'A'))
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', strings.ContainsRune("/._~+-", ch):
			escaped.WriteRune(ch)
		default:
			return "", fmt.Errorf("invalid Go module path or version: %q", part)
		}
	}
	return escaped.String(), nil
}

func (p preparer) redirected(ctx context.Context, address string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, address, nil)
	if err != nil {
		return false, err
	}
	client := *p.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return false, nil
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location, err := resp.Location()
		if err != nil {
			return false, fmt.Errorf("HEAD %s: invalid redirect", address)
		}
		return !strings.EqualFold(location.Hostname(), req.URL.Hostname()), nil
	}
	return false, fmt.Errorf("HEAD %s: HTTP %d", address, resp.StatusCode)
}

func archiveProxy(w io.Writer, stage string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	err := fs.WalkDir(os.DirFS(stage), "modproxy", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = path
		if err := tw.WriteHeader(header); err != nil || entry.IsDir() {
			return err
		}
		f, err := os.Open(filepath.Join(stage, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		return errors.Join(err, f.Close())
	})
	return errors.Join(err, tw.Close(), gz.Close())
}
