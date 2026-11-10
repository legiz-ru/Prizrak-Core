package xdrive

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A request that cannot be built, here for a control character in the URL,
// fails with a url.Error holding the whole URL, and a template can have a
// secret in it.
func TestTemplateBuildErrorHidesURL(t *testing.T) {
	tmpl := map[string]interface{}{
		"flatten": true,
		"put":     map[string]interface{}{"method": "PUT", "url": "http://127.0.0.1:9/folder/{name}?key={secret0}"},
		"get":     map[string]interface{}{"method": "GET", "url": "http://127.0.0.1:9/folder/{name}?key={secret0}"},
		"delete":  map[string]interface{}{"method": "DELETE", "url": "http://127.0.0.1:9/folder/{name}?key={secret0}"},
		"list": map[string]interface{}{
			"method":     "GET",
			"url":        "http://127.0.0.1:9/folder/?prefix={prefix}&key={secret0}",
			"namesRegex": `<href>([^<]+)</href>`,
		},
	}
	raw, _ := json.Marshal(tmpl)
	storage, err := newTemplateStorage(nil, &Config{
		RemoteFolder: "folder",
		Service:      "template",
		Secrets:      []string{"top-secret\x7f"},
		Template:     string(raw),
	})
	if err != nil {
		t.Fatalf("newTemplateStorage: %v", err)
	}
	defer storage.Close()
	err = storage.Put(context.Background(), "object", []byte("data"))
	if err == nil {
		t.Fatal("Put built a request from a URL with a control character")
	}
	if strings.Contains(err.Error(), "top-secret") {
		t.Fatalf("the secret is in the error: %v", err)
	}
}
