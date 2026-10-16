package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

const dbFile = "totally_not_my_privateKeys.db"

var db *sql.DB

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

	_, err = db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		pemBytes, exp,
	)
	return err
}

func initializeDB() error {
	var err error

	db, err = sql.Open("sqlite", dbFile)
	if err != nil {
		return err
	}

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
	var keyData []byte

	err := db.QueryRow(query, time.Now().Unix()).Scan(&kid, &keyData)
	if err != nil {
		return nil, 0, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, 0, fmt.Errorf("invalid PEM key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key, kid, err
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, expired := r.URL.Query()["expired"]

	key, kid, err := getKey(expired)
	if err != nil {
		http.Error(w, "Key not found", http.StatusInternalServerError)
		return
	}

	expiration := time.Now().Add(time.Hour).Unix()
	if expired {
		expiration = time.Now().Add(-time.Hour).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "userABC",
		"iat": time.Now().Unix(),
		"exp": expiration,
	})
	token.Header["kid"] = strconv.Itoa(kid)

	signedToken, err := token.SignedString(key)
	if err != nil {
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": signedToken,
	})
}

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
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	keys := []map[string]string{}

	for rows.Next() {
		var kid int
		var keyData []byte

		if err := rows.Scan(&kid, &keyData); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		block, _ := pem.Decode(keyData)
		if block == nil {
			continue
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			continue
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
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": keys,
	})
}

func newRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", authHandler)
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler)
	return mux
}

func main() {
	if err := initializeDB(); err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	handler := newRouter()

	fmt.Println("JWKS Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
