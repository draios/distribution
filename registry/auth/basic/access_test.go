package basic

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/registry/auth"
)

func TestBasicAccessController(t *testing.T) {
	testRealm := "The-Shire"
	testUsers := "bilbo"
	testPasswords := "baggins"

	options := map[string]interface{}{
		"realm":    testRealm,
		"user":     testUsers,
		"password": testPasswords,
	}
	ctx := context.Background()

	accessController, err := newAccessController(options)
	if err != nil {
		t.Fatal("error creating access controller")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithRequest(ctx, r)
		authCtx, err := accessController.Authorized(ctx)
		if err != nil {
			switch err := err.(type) {
			case auth.Challenge:
				err.SetHeaders(r, w)
				w.WriteHeader(http.StatusUnauthorized)
				return
			default:
				t.Fatalf("unexpected error authorizing request: %v", err)
			}
		}

		userInfo, ok := authCtx.Value(auth.UserKey).(auth.UserInfo)
		if !ok {
			t.Fatal("basic accessController did not set auth.user context")
		}

		if userInfo.Name != testUsers {
			t.Fatalf("expected user name %q, got %q", testUsers, userInfo.Name)
		}

		w.WriteHeader(http.StatusNoContent)
	}))

	client := &http.Client{
		CheckRedirect: nil,
	}

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error during GET: %v", err)
	}
	defer resp.Body.Close()

	// Request should not be authorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected non-fail response status: %v != %v", resp.StatusCode, http.StatusUnauthorized)
	}

	req, err = http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("error allocating new request: %v", err)
	}

	req.SetBasicAuth(testUsers, testPasswords)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error during GET: %v", err)
	}
	defer resp.Body.Close()

	// Request should be authorized
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected non-success response status: %v != %v for %s %s", resp.StatusCode, http.StatusNoContent, testUsers, testPasswords)
	}
}
