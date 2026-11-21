package claude

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

type Resource struct {
	Type      string `json:"type"`
	FileID    string `json:"file_id"`
	MountPath string `json:"mount_path"`
}

type Money struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

type Session struct {
	ID        string     `json:"id"`
	Resources []Resource `json:"resources"`
	Status    string     `json:"status"`
	Stats     struct {
		ActiveSeconds   float64 `json:"active_seconds"`
		DurationSeconds float64 `json:"duration_seconds"`
	} `json:"stats"`
	Usage struct {
		ActiveSeconds        float64 `json:"active_seconds"`
		InputTokens          int64   `json:"input_tokens"`
		OutputTokens         int64   `json:"output_tokens"`
		CacheReadInputTokens int64   `json:"cache_read_input_tokens"`
		CacheCreation        struct {
			Ephemeral5mInputTokens int64 `json:"ephemeral_5m_input_tokens"`
			Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
		} `json:"cache_creation"`
		ServerToolUse struct {
			WebFetchRequests  int64 `json:"web_fetch_requests"`
			WebSearchRequests int64 `json:"web_search_requests"`
		} `json:"server_tool_use"`
		ListCost Money `json:"list_cost"`
	} `json:"usage"`
}

func (c *Client) CreateSession(ctx context.Context, agentID, environmentID string, budgetCents int, resources []Resource) (Session, error) {
	type budget struct {
		Type        string `json:"type"`
		MaxListCost Money  `json:"max_list_cost"`
	}
	body, err := jsonBody(struct {
		Agent         string     `json:"agent"`
		EnvironmentID string     `json:"environment_id"`
		Budget        budget     `json:"budget"`
		Resources     []Resource `json:"resources"`
	}{agentID, environmentID, budget{"limit", Money{strconv.Itoa(budgetCents), "USD"}}, resources})
	if err != nil {
		return Session{}, err
	}
	var session Session
	_, err = c.json(ctx, http.MethodPost, "/v1/sessions", body, &session)
	if err == nil && session.ID == "" {
		err = errors.New("Managed Agents session response is missing a session ID")
	}
	return session, err
}

func (c *Client) GetSession(ctx context.Context, id string) (Session, error) {
	var session Session
	_, err := c.json(ctx, http.MethodGet, sessionPath(id), nil, &session)
	if err == nil && session.Status == "" {
		err = errors.New("Managed Agents session response is missing a status")
	}
	return session, err
}

func (c *Client) DeleteSession(ctx context.Context, id string) error {
	_, err := c.json(ctx, http.MethodDelete, sessionPath(id), nil, nil)
	return err
}

type event struct {
	Type    string      `json:"type"`
	Content []eventText `json:"content,omitempty"`
}

type eventText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (c *Client) SendUserMessage(ctx context.Context, id, text string) error {
	return c.sendEvent(ctx, id, event{Type: "user.message", Content: []eventText{{"text", text}}})
}

func (c *Client) Interrupt(ctx context.Context, id string) error {
	return c.sendEvent(ctx, id, event{Type: "user.interrupt"})
}

func (c *Client) sendEvent(ctx context.Context, id string, entry event) error {
	body, err := jsonBody(struct {
		Events []event `json:"events"`
	}{[]event{entry}})
	if err != nil {
		return err
	}
	_, err = c.json(ctx, http.MethodPost, eventsPath(id), body, nil)
	return err
}

func (c *Client) ListEvents(ctx context.Context, id string) (json.RawMessage, bool, error) {
	var events json.RawMessage
	_, err := c.json(ctx, http.MethodGet, eventsPath(id), nil, &events)
	if err != nil {
		return nil, false, err
	}
	var page struct {
		HasMore bool `json:"has_more"`
	}
	if err := json.Unmarshal(events, &page); err != nil {
		return events, false, errors.New("invalid Managed Agents event listing")
	}
	return events, page.HasMore, nil
}

func sessionPath(id string) string { return "/v1/sessions/" + url.PathEscape(id) }

func eventsPath(id string) string { return sessionPath(id) + "/events?beta=true" }
