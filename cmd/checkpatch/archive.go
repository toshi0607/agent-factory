package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func initArchive(archive, base string) error {
	if err := os.Mkdir(base, 0o755); err != nil {
		return fmt.Errorf("create archive base: %w", err)
	}
	if err := extractArchive(archive, base); err != nil {
		return fmt.Errorf("extract product archive: %w", err)
	}
	if _, err := git(base, nil, "init", "--template="); err != nil {
		return err
	}
	if _, err := git(base, nil, "add", "-f", "-A", "--"); err != nil {
		return err
	}
	_, err := git(base, nil, "-c", gitName, "-c", gitEmail, "-c", "core.hooksPath=/dev/null",
		"commit", "--no-gpg-sign", "--allow-empty", "-m", "Product archive baseline")
	return err
}

func extractArchive(archive, base string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer compressed.Close()
	root, err := os.OpenRoot(base)
	if err != nil {
		return err
	}
	defer root.Close()

	reader := tar.NewReader(compressed)
	var symlinks []tar.Header
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if name := h.Name; !filepath.IsLocal(name) || unsafeRelativePath(name) {
			return fmt.Errorf("unsafe archive path %q", name)
		}
		for component := range strings.SplitSeq(h.Name, "/") {
			if strings.EqualFold(component, ".git") {
				return fmt.Errorf("unsafe archive path %q", h.Name)
			}
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			// git archive stores the original commit ID in a global PAX header.
			continue
		}
		if err := root.MkdirAll(path.Dir(h.Name), 0o755); err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(h.Name, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			mode := os.FileMode(0o644) | h.FileInfo().Mode().Perm()&0o111
			dest, err := root.OpenFile(h.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(dest, reader)
			if err := errors.Join(err, dest.Close()); err != nil {
				return err
			}
		case tar.TypeSymlink:
			symlinks = append(symlinks, *h)
		default:
			return fmt.Errorf("unsupported archive entry %q (type %d)", h.Name, h.Typeflag)
		}
	}
	// Extract file contents before creating symlinks, so no archive entry can
	// redirect their writes. Root also prevents links escaping via a parent.
	for _, h := range symlinks {
		if err := root.Symlink(h.Linkname, h.Name); err != nil {
			return err
		}
	}
	// Read through the gzip trailer to validate its checksum.
	_, err = io.Copy(io.Discard, compressed)
	return err
}
