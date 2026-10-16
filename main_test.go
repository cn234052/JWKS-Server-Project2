package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setupTestDB(t *testing.T) {
	t.Helper()

	oldDB := db
	dir := t.TempDir()

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	db = nil

	t.Cleanup(func() {
		if db != nil {
			db.Close()
		}
		db = oldDB

		if err := os.Chdir(originalDir); err != nil {
			t.Error(err)
		}
	})

	if err := initializeDB(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, dbFile)); err != nil {
		t.Fatal(err)
	}
}

func TestInitializeDB(t *testing.T) {
	setupTestDB(t)

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count < 2 {
		t.Fatalf("expected at least 2 keys, got %d", count)
	}

	if err := initializeDB(); err != nil {
		t.Fatal(err)
	}
}

func TestInitializeDBMissingKeys(t *testing.T) {
	setupTestDB(t)

	if _, err := db.Exec("DELETE FROM keys WHERE exp > ?", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	if err := initializeDB(); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM keys WHERE exp > ?",
		time.Now().Unix(),
	).Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count == 0 {
		t.Fatal("valid key not regenerated")
	}

	if _, err := db.Exec("DELETE FROM keys WHERE exp <= ?", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	if err := initializeDB(); err != nil {
		t.Fatal(err)
	}

	if err := db.QueryRow(
		"SELECT COUNT(*) FROM keys WHERE exp <= ?",
		time.Now().Unix(),
	).Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count == 0 {
		t.Fatal("expired key not regenerated")
	}
}

func TestGetKey(t *testing.T) {
	setupTestDB(t)

	for _, expired := range []bool{false, true} {
		key, kid, err := getKey(expired)

		if err != nil {
			t.Fatal(err)
		}

		if key == nil || kid <= 0 {
			t.Fatal("invalid key returned")
		}
	}

	if _, err := db.Exec("DELETE FROM keys"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := getKey(false); err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestAuthHandler(t *testing.T) {
	setupTestDB(t)

	for _, path := range []string{"/auth", "/auth?expired=true"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()

		authHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status: %d", rec.Code)
		}

		var result struct {
			Token string `json:"token"`
		}

		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}

		if result.Token == "" {
			t.Fatal("missing JWT")
		}

		token, _, err := jwt.NewParser().ParseUnverified(
			result.Token, jwt.MapClaims{},
		)
		if err != nil {
			t.Fatal(err)
		}

		if token.Header["kid"] == nil {
			t.Fatal("missing kid")
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rec := httptest.NewRecorder()
	authHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal("expected method not allowed")
	}

	if _, err := db.Exec("DELETE FROM keys"); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec = httptest.NewRecorder()
	authHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatal("expected missing key error")
	}
}

func TestJWKSHandler(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	)
	rec := httptest.NewRecorder()
	jwksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}

	var result struct {
		Keys []map[string]string `json:"keys"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	if len(result.Keys) == 0 {
		t.Fatal("expected valid JWK")
	}

	req = httptest.NewRequest(
		http.MethodPost, "/.well-known/jwks.json", nil,
	)
	rec = httptest.NewRecorder()
	jwksHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal("expected method not allowed")
	}
}

func TestSaveKey(t *testing.T) {
	setupTestDB(t)

	if err := saveKey(time.Now().Add(3 * time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count < 3 {
		t.Fatal("key was not saved")
	}
}

func TestInvalidPEM(t *testing.T) {
	setupTestDB(t)

	if _, err := db.Exec("DELETE FROM keys"); err != nil {
		t.Fatal(err)
	}

	_, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		[]byte("invalid PEM"),
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := getKey(false); err == nil {
		t.Fatal("expected invalid PEM error")
	}

	req := httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	)
	rec := httptest.NewRecorder()
	jwksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatal("expected valid response")
	}
}

func TestInvalidRSAKey(t *testing.T) {
	setupTestDB(t)

	if _, err := db.Exec("DELETE FROM keys"); err != nil {
		t.Fatal(err)
	}

	invalidKey := []byte(
		"-----BEGIN RSA PRIVATE KEY-----\n" +
			"YWJj\n" +
			"-----END RSA PRIVATE KEY-----\n",
	)

	_, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		invalidKey,
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := getKey(false); err == nil {
		t.Fatal("expected RSA parsing error")
	}

	req := httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	)
	rec := httptest.NewRecorder()
	jwksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestJWKSDatabaseError(t *testing.T) {
	setupTestDB(t)

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	)
	rec := httptest.NewRecorder()
	jwksHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestAuthDatabaseError(t *testing.T) {
	setupTestDB(t)

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()
	authHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestSaveKeyDatabaseError(t *testing.T) {
	setupTestDB(t)

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if err := saveKey(time.Now().Add(time.Hour).Unix()); err == nil {
		t.Fatal("expected database error")
	}
}

func TestNewRouter(t *testing.T) {
	setupTestDB(t)

	router := newRouter()

	req := httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
