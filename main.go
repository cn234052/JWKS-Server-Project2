
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

const dbFile = "totally_not_my_privateKeys.db"

var db *sql.DB

// AES encryption key from environment.
func encryptionKey() ([]byte, error) {
	value := os.Getenv("NOT_MY_KEY")
	if value == "" {
		return nil, errors.New("NOT_MY_KEY is not set")
	}

	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, errors.New("NOT_MY_KEY must be a base64-encoded 32-byte key")
	}
	return key, nil
}

// Encrypt private keys using AES-256-GCM.
func encryptKey(data []byte) ([]byte, error) {
	key, err := encryptionKey()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt private keys.
func decryptKey(data []byte) ([]byte, error) {
	key, err := encryptionKey()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	size := gcm.NonceSize()
	if len(data) < size {
		return nil, errors.New("invalid encrypted key")
	}

	return gcm.Open(nil, data[:size], data[size:], nil)
}

// Save a new RSA private key encrypted in SQLite.
func saveKey(exp int64) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	encrypted, err := encryptKey(pemBytes)
	if err != nil {
		return err
	}

	_, err = db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		encrypted, exp,
	)
	return err
}

// Initialize the database and tables.
func initializeDB() error {
	var err error

	if _, err = encryptionKey(); err != nil {
		return err
	}

	db, err = sql.Open("sqlite", dbFile)
	if err != nil {
		return err
	}

	db.SetMaxOpenConns(1)

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			exp INTEGER NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			email TEXT UNIQUE,
			date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS auth_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_ip TEXT NOT NULL,
			request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			user_id INTEGER,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		return err
	}

	// Encrypt any plaintext keys left from Project 2.
	rows, err := db.Query("SELECT kid, key FROM keys")
	if err != nil {
		return err
	}

	type oldKey struct {
		id   int
		data []byte
	}

	var oldKeys []oldKey

	for rows.Next() {
		var item oldKey
		if err := rows.Scan(&item.id, &item.data); err != nil {
			rows.Close()
			return err
		}

		if block, _ := pem.Decode(item.data); block != nil {
			oldKeys = append(oldKeys, item)
		}
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, item := range oldKeys {
		encrypted, err := encryptKey(item.data)
		if err != nil {
			return err
		}

		_, err = db.Exec(
			"UPDATE keys SET key = ? WHERE kid = ?",
			encrypted, item.id,
		)
		if err != nil {
			return err
		}
	}

	now := time.Now().Unix()

	var validCount int
	err = db.QueryRow(
		"SELECT COUNT(*) FROM keys WHERE exp > ?", now,
	).Scan(&validCount)
	if err != nil {
		return err
	}

	if validCount == 0 {
		if err := saveKey(time.Now().Add(2 * time.Hour).Unix()); err != nil {
			return err
		}
	}

	var expiredCount int
	err = db.QueryRow(
		"SELECT COUNT(*) FROM keys WHERE exp <= ?", now,
	).Scan(&expiredCount)
	if err != nil {
		return err
	}

	if expiredCount == 0 {
		if err := saveKey(time.Now().Add(-time.Hour).Unix()); err != nil {
			return err
		}
	}

	return nil
}

// Retrieve a valid or expired RSA private key.
func getKey(expired bool) (*rsa.PrivateKey, int, error) {
	operator := ">"
	if expired {
		operator = "<="
	}

	query := fmt.Sprintf(
		"SELECT kid, key FROM keys WHERE exp %s ? ORDER BY exp DESC LIMIT 1",
		operator,
	)

	var kid int
	var encrypted []byte

	err := db.QueryRow(
		query, time.Now().Unix(),
	).Scan(&kid, &encrypted)
	if err != nil {
		return nil, 0, err
	}

	data, err := decryptKey(encrypted)
	if err != nil {
		return nil, 0, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, 0, errors.New("invalid PEM key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key, kid, err
}

// Hash passwords using Argon2id with a random salt.
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)

	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		3,
		64*1024,
		2,
		32,
	)

	return fmt.Sprintf(
		"argon2id$v=19$m=65536,t=3,p=2$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// POST /register
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	user.Username = strings.TrimSpace(user.Username)
	user.Email = strings.TrimSpace(user.Email)

	if user.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Generate a secure UUIDv4 password.
	password, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, "Password generation failed", 500)
		return
	}

	passwordHash, err := hashPassword(password.String())
	if err != nil {
		http.Error(w, "Password hashing failed", 500)
		return
	}

	var email interface{}
	if user.Email != "" {
		email = user.Email
	}

	_, err = db.Exec(
		"INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
		user.Username,
		passwordHash,
		email,
	)

	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			http.Error(w, "Username or email already exists", http.StatusConflict)
			return
		}

		http.Error(w, "Registration failed", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"password": password.String(),
	})
}

// Rate limiter: 10 requests per second.
type rateLimiter struct {
	mu       sync.Mutex
	requests []time.Time
}

func (l *rateLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Second)

	active := l.requests[:0]
	for _, t := range l.requests {
		if t.After(cutoff) {
			active = append(active, t)
		}
	}

	l.requests = active

	if len(l.requests) >= 10 {
		return false
	}

	l.requests = append(l.requests, now)
	return true
}

var authLimiter rateLimiter

// POST /auth
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !authLimiter.allow() {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	var request struct {
		Username string `json:"username"`
	}

	// An empty body is supported for Project 2 compatibility.
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&request)
	}

	_, expired := r.URL.Query()["expired"]

	key, kid, err := getKey(expired)
	if err != nil {
		http.Error(w, "Key not found", 500)
		return
	}

	expiration := time.Now().Add(time.Hour).Unix()
	if expired {
		expiration = time.Now().Add(-time.Hour).Unix()
	}

	subject := "userABC"
	if request.Username != "" {
		subject = request.Username
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": expiration,
	})

	token.Header["kid"] = strconv.Itoa(kid)

	signedToken, err := token.SignedString(key)
	if err != nil {
		http.Error(w, "Signing failed", 500)
		return
	}

	var userID interface{}

	if request.Username != "" {
		var id int
		err := db.QueryRow(
			"SELECT id FROM users WHERE username = ?",
			request.Username,
		).Scan(&id)

		if err == nil {
			userID = id
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	// Only successfully processed authentication
	// requests are recorded.
	_, err = db.Exec(
		"INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
		ip, userID,
	)

	if err != nil {
		http.Error(w, "Authentication logging failed", 500)
		return
	}

	if userID != nil {
		_, _ = db.Exec(
			"UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
			userID,
		)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": signedToken,
	})
}

// GET /.well-known/jwks.json
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.Query(
		"SELECT kid, key FROM keys WHERE exp > ?",
		time.Now().Unix(),
	)

	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	defer rows.Close()

	keys := []map[string]string{}

	for rows.Next() {
		var kid int
		var encrypted []byte

		if err := rows.Scan(&kid, &encrypted); err != nil {
			http.Error(w, "Database error", 500)
			return
		}

		data, err := decryptKey(encrypted)
		if err != nil {
			http.Error(w, "Decryption failed", 500)
			return
		}

		block, _ := pem.Decode(data)
		if block == nil {
			http.Error(w, "Invalid key", 500)
			return
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			http.Error(w, "Invalid RSA key", 500)
			return
		}

		publicKey := privateKey.PublicKey

		n := base64.RawURLEncoding.EncodeToString(
			publicKey.N.Bytes(),
		)

		e := base64.RawURLEncoding.EncodeToString(
			big.NewInt(int64(publicKey.E)).Bytes(),
		)

		keys = append(keys, map[string]string{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": strconv.Itoa(kid),
			"n":   n,
			"e":   e,
		})
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Database error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": keys,
	})
}

// Configure server endpoints.
func newRouter() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/auth", authHandler)
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler)

	return mux
}

func main() {
	if err := initializeDB(); err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	fmt.Println("JWKS Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", newRouter()))
}
