package claude

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
)

type resourceID struct {
	ID string `json:"id"`
}

func (c *Client) CreateEnvironment(ctx context.Context, name string, allowedHosts []string) (id, requestSHA256 string, err error) {
	type networking struct {
		Type         string   `json:"type"`
		AllowedHosts []string `json:"allowed_hosts"`
	}
	type config struct {
		Type       string     `json:"type"`
		Networking networking `json:"networking"`
	}
	body := struct {
		Name   string `json:"name"`
		Config config `json:"config"`
	}{name, config{"cloud", networking{"limited", allowedHosts}}}
	var resource resourceID
	hash, err := c.create(ctx, "/v1/environments", body, &resource)
	return resource.ID, hash, resource.checkID(err)
}

func (c *Client) CreateAgent(ctx context.Context, name, model, system string) (id, requestSHA256 string, err error) {
	const toolsetType = "agent_toolset_20260401"
	type defaults struct {
		Enabled *bool `json:"enabled"`
	}
	type config struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	type toolset struct {
		Type          string   `json:"type"`
		DefaultConfig defaults `json:"default_config"`
		Configs       []config `json:"configs"`
	}
	configs := make([]config, 0, 6)
	for _, name := range []string{"bash", "read", "write", "edit", "glob", "grep"} {
		configs = append(configs, config{name, true})
	}
	body := struct {
		Name   string    `json:"name"`
		Model  string    `json:"model"`
		System string    `json:"system"`
		Tools  []toolset `json:"tools"`
	}{name, model, system, []toolset{{toolsetType, defaults{new(false)}, configs}}}
	var resource struct {
		resourceID
		Tools json.RawMessage `json:"tools"`
	}
	hash, err := c.create(ctx, "/v1/agents", body, &resource)
	if err := resource.checkID(err); err != nil {
		return resource.ID, hash, err
	}
	unconfirmed := errors.New("agent response does not confirm that web tools are disabled")
	var toolsets []toolset
	if err := json.Unmarshal(resource.Tools, &toolsets); err != nil {
		return resource.ID, hash, unconfirmed
	}
	found := false
	for _, tools := range toolsets {
		if tools.Type != toolsetType {
			continue
		}
		if tools.DefaultConfig.Enabled == nil || *tools.DefaultConfig.Enabled ||
			slices.ContainsFunc(tools.Configs, func(cfg config) bool {
				return cfg.Enabled && (cfg.Name == "web_fetch" || cfg.Name == "web_search")
			}) {
			return resource.ID, hash, unconfirmed
		}
		found = true
	}
	if !found {
		return resource.ID, hash, unconfirmed
	}
	return resource.ID, hash, nil
}

func (c *Client) create(ctx context.Context, path string, body, resource any) (string, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	_, err = c.json(ctx, http.MethodPost, path, bytes.NewReader(data), resource)
	return hash, err
}

func (r resourceID) checkID(err error) error {
	if err == nil && r.ID == "" {
		return errors.New("Managed Agents response is missing a resource ID")
	}
	return err
}

func (c *Client) CheckAgents(ctx context.Context) (int, error) {
	return c.json(ctx, http.MethodGet, "/v1/agents?limit=1", nil, nil)
}

type MessagesCheck struct {
	HTTPStatus       int    `json:"messages_http_status"`
	Model            string `json:"model,omitempty"`
	InputTokens      *int   `json:"input_tokens,omitempty"`
	OutputTokens     *int   `json:"output_tokens,omitempty"`
	ErrorType        string `json:"error_type,omitempty"`
	RequestIDPresent bool   `json:"request_id_present"`
}

func (c *Client) CheckMessages(ctx context.Context, model string) (MessagesCheck, error) {
	type message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	body, err := jsonBody(struct {
		Model     string    `json:"model"`
		MaxTokens int       `json:"max_tokens"`
		Messages  []message `json:"messages"`
	}{model, 8, []message{{"user", "Reply with OK."}}})
	var check MessagesCheck
	if err != nil {
		return check, err
	}
	_, err = c.request(ctx, http.MethodPost, "/v1/messages", "application/json", body, -1, requestTimeout, nil, &check)
	return check, err
}

func (check *MessagesCheck) readResponse(resp *http.Response, authHeaders http.Header) error {
	check.HTTPStatus = resp.StatusCode
	check.RequestIDPresent = resp.Header.Get("request-id") != ""
	if resp.StatusCode != http.StatusOK {
		var diagnostic struct {
			Error struct {
				Type string `json:"type"`
			} `json:"error"`
		}
		apiErr := &HTTPError{StatusCode: resp.StatusCode}
		if json.NewDecoder(resp.Body).Decode(&diagnostic) == nil {
			errorType := errorBody(strings.NewReader(diagnostic.Error.Type), authHeaders)
			if errorType != "" && !credentialPattern.MatchString(errorType) {
				check.ErrorType = errorType
				diagnostic.Error.Type = errorType
				body, _ := json.Marshal(diagnostic)
				apiErr.Body = string(body)
			}
		}
		return apiErr
	}
	var result struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errors.New("invalid Messages API JSON response")
	}
	check.Model = result.Model
	check.InputTokens = new(result.Usage.InputTokens)
	check.OutputTokens = new(result.Usage.OutputTokens)
	return nil
}

func (c *Client) ArchiveAgent(ctx context.Context, id string) error {
	_, err := c.json(ctx, http.MethodPost, "/v1/agents/"+url.PathEscape(id)+"/archive", nil, nil)
	return err
}

func (c *Client) DeleteEnvironment(ctx context.Context, id string) error {
	path := "/v1/environments/" + url.PathEscape(id)
	_, deleteErr := c.json(ctx, http.MethodDelete, path, nil, nil)
	if deleteErr == nil {
		return nil
	}
	_, archiveErr := c.json(ctx, http.MethodPost, path+"/archive", nil, nil)
	if archiveErr == nil || IsNotFound(archiveErr) {
		return nil
	}
	return errors.Join(deleteErr, archiveErr)
}

func IsNotFound(err error) bool {
	status, ok := errors.AsType[*HTTPError](err)
	return ok && status.StatusCode == http.StatusNotFound
}

type File struct {
	ID        string `json:"id"`
	Filename  string `json:"filename"`
	CreatedAt string `json:"created_at"`
}

func (c *Client) UploadFile(ctx context.Context, name string, content io.Reader) (File, error) {
	var result File
	var frame bytes.Buffer
	form := multipart.NewWriter(&frame)
	if _, err := form.CreateFormFile("file", name); err != nil {
		return result, err
	}
	offset := frame.Len()
	if err := form.Close(); err != nil {
		return result, err
	}
	prefix, suffix := frame.Bytes()[:offset], frame.Bytes()[offset:]
	size := int64(-1)
	if f, ok := content.(*os.File); ok {
		info, statErr := f.Stat()
		pos, seekErr := f.Seek(0, io.SeekCurrent)
		if statErr == nil && seekErr == nil && info.Mode().IsRegular() && pos <= info.Size() {
			size = int64(frame.Len()) + info.Size() - pos
		}
	}

	body := io.MultiReader(bytes.NewReader(prefix), content, bytes.NewReader(suffix))
	_, err := c.request(ctx, http.MethodPost, "/v1/files", form.FormDataContentType(), body, size, fileTimeout,
		func(r io.Reader) error {
			if err := json.NewDecoder(r).Decode(&result); err != nil {
				return errors.New("invalid Managed Agents file upload response")
			}
			return nil
		}, nil)
	if err == nil && result.ID == "" {
		err = errors.New("Managed Agents upload response is missing a file ID")
	}
	return result, err
}

func (c *Client) ListSessionFiles(ctx context.Context, sessionID string) ([]File, bool, error) {
	var result struct {
		Data    []File `json:"data"`
		HasMore bool   `json:"has_more"`
	}
	query := url.Values{"scope_id": {sessionID}}
	_, err := c.json(ctx, http.MethodGet, "/v1/files?"+query.Encode(), nil, &result)
	return result.Data, result.HasMore, err
}

func (c *Client) DownloadFile(ctx context.Context, id string, w io.Writer) error {
	_, err := c.request(ctx, http.MethodGet, "/v1/files/"+url.PathEscape(id)+"/content", "", nil, -1, fileTimeout,
		func(r io.Reader) error {
			_, err := io.Copy(w, r)
			return err
		}, nil)
	return err
}

func (c *Client) DeleteFile(ctx context.Context, id string) error {
	_, err := c.json(ctx, http.MethodDelete, "/v1/files/"+url.PathEscape(id), nil, nil)
	return err
}
