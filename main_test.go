
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Create a separate temporary database for testing.
func setupTestDB(t *testing.T) {
	t.Helper()

	oldDB := db
	oldLimiter := authLimiter.requests

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	t.Setenv("NOT_MY_KEY", base64.StdEncoding.EncodeToString(key))

	var err error
	db, err = sql.Open("sqlite", t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}

	db.SetMaxOpenConns(1)

	statements := []string{
		`CREATE TABLE keys (
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			exp INTEGER NOT NULL
		)`,
		`CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			email TEXT UNIQUE,
			date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP
		)`,
		`CREATE TABLE auth_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_ip TEXT NOT NULL,
			request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			user_id INTEGER,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)`,
	}

	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}

	authLimiter.requests = nil

	t.Cleanup(func() {
		db.Close()
		db = oldDB
		authLimiter.requests = oldLimiter
	})
}

func TestEncryptionKey(t *testing.T) {
	t.Setenv("NOT_MY_KEY", "")

	if _, err := encryptionKey(); err == nil {
		t.Fatal("Expected error for missing encryption key")
	}

	t.Setenv("NOT_MY_KEY", "invalid")

	if _, err := encryptionKey(); err == nil {
		t.Fatal("Expected error for invalid encryption key")
	}

	key := make([]byte, 32)
	t.Setenv("NOT_MY_KEY", base64.StdEncoding.EncodeToString(key))

	result, err := encryptionKey()
	if err != nil || len(result) != 32 {
		t.Fatal("Expected valid 32-byte key")
	}
}

func TestAESEncryption(t *testing.T) {
	setupTestDB(t)

	original := []byte("private RSA key test data")

	encrypted, err := encryptKey(original)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(encrypted, original) {
		t.Fatal("Private key stored as plaintext")
	}

	decrypted, err := decryptKey(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(original, decrypted) {
		t.Fatal("Decrypted data does not match original")
	}

	// Random nonces should produce different ciphertexts.
	encrypted2, err := encryptKey(original)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(encrypted, encrypted2) {
		t.Fatal("Encryption should use a random nonce")
	}
}

func TestAESInvalidData(t *testing.T) {
	setupTestDB(t)

	if _, err := decryptKey([]byte("short")); err == nil {
		t.Fatal("Expected decryption error")
	}

	encrypted, err := encryptKey([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	encrypted[len(encrypted)-1] ^= 1

	if _, err := decryptKey(encrypted); err == nil {
		t.Fatal("Tampered ciphertext should fail")
	}
}

func TestAESMissingKey(t *testing.T) {
	setupTestDB(t)
	t.Setenv("NOT_MY_KEY", "")

	if _, err := encryptKey([]byte("secret")); err == nil {
		t.Fatal("Expected encryption error")
	}

	if _, err := decryptKey([]byte("secret")); err == nil {
		t.Fatal("Expected decryption error")
	}
}

func TestHashPassword(t *testing.T) {
	hash1, err := hashPassword("mypassword")
	if err != nil {
		t.Fatal(err)
	}

	hash2, err := hashPassword("mypassword")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(hash1, "argon2id$") {
		t.Fatal("Expected Argon2id password hash")
	}

	if hash1 == hash2 {
		t.Fatal("Password hashes should use random salts")
	}

	if strings.Contains(hash1, "mypassword") {
		t.Fatal("Password must not be stored in plaintext")
	}
}

func TestRegisterSuccess(t *testing.T) {
	setupTestDB(t)

	body := `{"username":"charite","email":"charite@example.com"}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/register",
		strings.NewReader(body),
	)

	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var response struct {
		Password string `json:"password"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	password, err := uuid.Parse(response.Password)
	if err != nil || password.Version() != 4 {
		t.Fatal("Expected UUIDv4 password")
	}

	var storedHash string
	err = db.QueryRow(
		"SELECT password_hash FROM users WHERE username = ?",
		"charite",
	).Scan(&storedHash)

	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(storedHash, "argon2id$") {
		t.Fatal("Expected Argon2id hash in database")
	}

	if storedHash == response.Password {
		t.Fatal("Password stored in plaintext")
	}
}

func TestRegisterDuplicate(t *testing.T) {
	setupTestDB(t)

	body := `{"username":"duplicate","email":"duplicate@example.com"}`

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(
			http.MethodPost,
			"/register",
			strings.NewReader(body),
		)

		rec := httptest.NewRecorder()
		registerHandler(rec, req)

		expected := http.StatusCreated
		if i == 1 {
			expected = http.StatusConflict
		}

		if rec.Code != expected {
			t.Fatalf("Expected %d, got %d", expected, rec.Code)
		}
	}
}

func TestRegisterInvalidRequests(t *testing.T) {
	setupTestDB(t)

	cases := []struct {
		method string
		body   string
		status int
	}{
		{"GET", "", 405},
		{"POST", "{invalid", 400},
		{"POST", `{}`, 400},
		{"POST", `{"username":"   "}`, 400},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(
			tc.method,
			"/register",
			strings.NewReader(tc.body),
		)

		rec := httptest.NewRecorder()
		registerHandler(rec, req)

		if rec.Code != tc.status {
			t.Errorf("Expected %d, got %d", tc.status, rec.Code)
		}
	}
}

func TestSaveAndGetKey(t *testing.T) {
	setupTestDB(t)

	if err := saveKey(time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	if err := saveKey(time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	key, kid, err := getKey(false)
	if err != nil || key == nil || kid == 0 {
		t.Fatal("Failed to retrieve valid key:", err)
	}

	expiredKey, expiredKid, err := getKey(true)
	if err != nil || expiredKey == nil || expiredKid == 0 {
		t.Fatal("Failed to retrieve expired key:", err)
	}

	var stored []byte
	err = db.QueryRow(
		"SELECT key FROM keys WHERE kid = ?",
		kid,
	).Scan(&stored)

	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("Private key is not encrypted")
	}
}

func TestGetKeyNotFound(t *testing.T) {
	setupTestDB(t)

	if _, _, err := getKey(false); err == nil {
		t.Fatal("Expected error when key is missing")
	}
}

func TestJWKSHandler(t *testing.T) {
	setupTestDB(t)

	if err := saveKey(time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var result struct {
		Keys []map[string]string `json:"keys"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	if len(result.Keys) != 1 {
		t.Fatalf("Expected 1 key, got %d", len(result.Keys))
	}

	if result.Keys[0]["kty"] != "RSA" {
		t.Fatal("Expected RSA public key")
	}

	if result.Keys[0]["n"] == "" || result.Keys[0]["e"] == "" {
		t.Fatal("Missing public key parameters")
	}
}

func TestJWKSInvalidMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	jwksHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal("Expected 405")
	}
}

func TestAuthSuccessAndLogging(t *testing.T) {
	setupTestDB(t)

	if err := saveKey(time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	_, err := db.Exec(
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		"testuser", "argon2id$test",
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		strings.NewReader(`{"username":"testuser"}`),
	)

	req.RemoteAddr = "192.168.1.10:12345"

	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var response struct {
		Token string `json:"token"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	if response.Token == "" {
		t.Fatal("Expected JWT token")
	}

	var ip string
	var userID sql.NullInt64

	err = db.QueryRow(
		"SELECT request_ip, user_id FROM auth_logs LIMIT 1",
	).Scan(&ip, &userID)

	if err != nil {
		t.Fatal(err)
	}

	if ip != "192.168.1.10" {
		t.Fatalf("Incorrect logged IP: %s", ip)
	}

	if !userID.Valid {
		t.Fatal("Expected registered user ID in auth log")
	}
}

func TestAuthExpiredToken(t *testing.T) {
	setupTestDB(t)

	if err := saveKey(time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth?expired=true",
		nil,
	)

	rec := httptest.NewRecorder()
	authHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}
}

func TestAuthInvalidMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rec := httptest.NewRecorder()

	authHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal("Expected 405")
	}
}

func TestAuthMissingKey(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()

	authHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rec.Code)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM auth_logs").Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatal("Failed authentication should not be logged")
	}
}

func TestRateLimiter(t *testing.T) {
	var limiter rateLimiter

	for i := 0; i < 10; i++ {
		if !limiter.allow() {
			t.Fatalf("Request %d should be allowed", i+1)
		}
	}

	if limiter.allow() {
		t.Fatal("11th request should be blocked")
	}

	limiter.requests = []time.Time{
		time.Now().Add(-2 * time.Second),
	}

	if !limiter.allow() {
		t.Fatal("Request should be allowed after window expires")
	}
}

func TestAuthRateLimitHTTP(t *testing.T) {
	setupTestDB(t)

	authLimiter.requests = make([]time.Time, 10)
	for i := range authLimiter.requests {
		authLimiter.requests[i] = time.Now()
	}

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()

	authHandler(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 429, got %d", rec.Code)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM auth_logs").Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatal("Rate-limited requests should not be logged")
	}
}

func TestAESKeyLength(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		key := make([]byte, size)
		if _, err := aes.NewCipher(key); err != nil {
			t.Fatalf("AES key size %d should work: %v", size, err)
		}
	}
}

func TestInitializeDBMissingKey(t *testing.T) {
	t.Setenv("NOT_MY_KEY", "")

	err := initializeDB()

	if err == nil {
		t.Fatal("Expected an error when NOT_MY_KEY is missing")
	}
}


func TestInitializeDBSuccess(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	t.Setenv("NOT_MY_KEY", base64.StdEncoding.EncodeToString(key))

	// Run in a temporary directory to avoid modifying
	// the real project database.
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	defer os.Chdir(oldDir)

	oldDB := db
	defer func() {
		if db != nil {
			db.Close()
		}
		db = oldDB
	}()

	if err := initializeDB(); err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{"keys", "users", "auth_logs"} {
		var name string
		err := db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?",
			table,
		).Scan(&name)

		if err != nil {
			t.Fatalf("Table %s was not created: %v", table, err)
		}
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count < 2 {
		t.Fatal("Expected valid and expired RSA keys")
	}
}


func TestJWKSInvalidEncryptedKey(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		[]byte("invalid encrypted data"),
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	rec := httptest.NewRecorder()
	jwksHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rec.Code)
	}
}

func TestJWKSInvalidPEM(t *testing.T) {
	setupTestDB(t)

	encrypted, err := encryptKey([]byte("not a PEM key"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		encrypted,
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	rec := httptest.NewRecorder()
	jwksHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rec.Code)
	}
}

func TestJWKSDatabaseError(t *testing.T) {
	setupTestDB(t)

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	rec := httptest.NewRecorder()
	jwksHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rec.Code)
	}
}

func TestJWKSInvalidRSAKey(t *testing.T) {
	setupTestDB(t)

	pemData := []byte(
		"-----BEGIN RSA PRIVATE KEY-----\n" +
			"aW52YWxpZCBrZXk=\n" +
			"-----END RSA PRIVATE KEY-----\n",
	)

	encrypted, err := encryptKey(pemData)
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		encrypted,
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	rec := httptest.NewRecorder()
	jwksHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rec.Code)
	}
}

func TestJWKSEmptyKeys(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	rec := httptest.NewRecorder()
	jwksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var result struct {
		Keys []map[string]string `json:"keys"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	if len(result.Keys) != 0 {
		t.Fatal("Expected empty JWKS")
	}
}

func TestGetKeyInvalidEncryptedData(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		[]byte("corrupted private key"),
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatal(err)
	}

	key, kid, err := getKey(false)

	if err == nil {
		t.Fatal("Expected error for corrupted encrypted key")
	}

	if key != nil || kid != 0 {
		t.Fatal("Expected no key to be returned")
	}
}

func TestGetKeyInvalidPEM(t *testing.T) {
	setupTestDB(t)

	encrypted, err := encryptKey([]byte("not a valid PEM key"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		encrypted,
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatal(err)
	}

	key, kid, err := getKey(false)

	if err == nil {
		t.Fatal("Expected error for invalid PEM key")
	}

	if key != nil || kid != 0 {
		t.Fatal("Expected no private key")
	}
}



