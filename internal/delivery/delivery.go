// Package delivery defines the manifest shared by prepare and session start.
package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const ManifestName = "manifest.json"

type Manifest struct {
	Task       string `json:"task"`
	BaseCommit string `json:"base_commit"`
	Files      []File `json:"files"`
}

type File struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Write keeps each file object on its own line for the sandbox shell parser.
func (m Manifest) Write(w io.Writer) error {
	task, err := json.Marshal(m.Task)
	if err != nil {
		return err
	}
	base, err := json.Marshal(m.BaseCommit)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "{\"task\":%s,\"base_commit\":%s,\"files\":[\n", task, base); err != nil {
		return err
	}
	for i, file := range m.Files {
		data, err := json.Marshal(file)
		if err != nil {
			return err
		}
		if i > 0 {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return err
			}
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	_, err = io.WriteString(w, "\n]}\n")
	return err
}

func Digest(r io.Reader) (string, int64, error) {
	hash := sha256.New()
	n, err := io.Copy(hash, r)
	return hex.EncodeToString(hash.Sum(nil)), n, err
}

func Inspect(path string) (File, error) {
	f, err := os.Open(path)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	hash, size, err := Digest(f)
	return File{Name: filepath.Base(path), SHA256: hash, Bytes: size}, err
}

func WriteAtomic(path string, write func(io.Writer) error) error {
	return writeTemporary(path, write, os.Rename)
}

func WriteNew(path string, write func(io.Writer) error) error {
	return writeTemporary(path, write, os.Link)
}

func writeTemporary(path string, write func(io.Writer) error, publish func(string, string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".factory-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := errors.Join(write(f), f.Close()); err != nil {
		return err
	}
	return publish(f.Name(), path)
}
