package keycloak

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

type WebHook struct {
	Id         string   `json:"id"`
	Enabled    bool     `json:"enabled"`
	Secret     string   `json:"secret"`
	Url        string   `json:"url"`
	CreatedBy  string   `json:"createdBy"`
	CreatedAt  int64    `json:"createdAt"`
	Realm      string   `json:"realm"`
	EventTypes []string `json:"eventTypes"`
}

var (
	ErrNotFound = errors.New("not found")
)

func (k *KeycloakClient) GetWebhooks(ctx context.Context, realmId string) (w []WebHook, err error) {
	if err = k.get(ctx, fmt.Sprintf("/realms/%s/webhooks", realmId), &w, nil); err != nil {
		return nil, err
	}

	return w, nil
}

func (k *KeycloakClient) GetWebhook(ctx context.Context, realmId, id string) (w WebHook, err error) {
	// corrupted response
	//if err = keycloakClient.get(ctx, fmt.Sprintf("/realms/%s/webhooks/%s", realmId, id), &w, nil); err != nil {
	//	return WebHook{}, err
	//}
	//return w, nil

	// use another way: receive all webhooks and try find one by id

	var ws []WebHook
	if ws, err = k.GetWebhooks(ctx, realmId); err != nil {
		return WebHook{}, err
	}

	var i = slices.IndexFunc(ws, func(hook WebHook) bool {
		return hook.Id == id
	})

	if i == -1 {
		return WebHook{}, ErrNotFound
	}

	return ws[i], nil
}

func (k *KeycloakClient) CreateWebhooks(ctx context.Context, realmId string, w *WebHook) (err error) {
	var location string
	if _, location, err = k.post(ctx, fmt.Sprintf("/realms/%s/webhooks", realmId), w); err != nil {
		return err
	}

	w.Id = getIdFromLocationHeader(location)

	var wf WebHook
	if wf, err = k.GetWebhook(ctx, realmId, w.Id); err != nil {
		return err
	}

	w.CreatedAt = wf.CreatedAt
	w.CreatedBy = wf.CreatedBy

	return nil
}

func (k *KeycloakClient) UpdateWebhooks(ctx context.Context, realmId string, w *WebHook) (err error) {
	if err = k.put(ctx, fmt.Sprintf("/realms/%s/webhooks/%s", realmId, w.Id), w); err != nil {
		return err
	}
	return nil
}

func (k *KeycloakClient) DeleteWebhooks(ctx context.Context, realmId string, w *WebHook) (err error) {
	if err = k.delete(ctx, fmt.Sprintf("/realms/%s/webhooks/%s", realmId, w.Id), w); err != nil {
		return err
	}
	return nil
}

func getIdFromLocationHeader(locationHeader string) string {
	var i = strings.LastIndex(locationHeader, "/")
	if i == -1 {
		return locationHeader
	}

	if i+1 >= len(locationHeader) {
		return ""
	}

	return locationHeader[i+1:]
}
