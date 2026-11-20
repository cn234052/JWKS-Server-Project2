# JWKS Server – Project 3

**CSCE 3550 – Foundations of Cybersecurity**

## About the Project

For Project 3, I improved my JWKS server using Go and SQLite by adding stronger security features. The server now encrypts RSA private keys, supports user registration, securely hashes passwords, and records authentication requests.

## Features

- Stores RSA private keys in SQLite using AES-256-GCM encryption.
- Uses the `NOT_MY_KEY` environment variable for encryption.
- Generates valid and expired JWT tokens.
- Provides public keys through the JWKS endpoint.
- Supports user registration with randomly generated UUIDv4 passwords.
- Uses Argon2id to securely hash passwords.
- Records authentication requests in the database.
- Includes rate limiting of 10 authentication requests per second.

## How to Run

First, install the required dependencies:

```bash
go mod tidy
```

Set the encryption key:

```bash
export NOT_MY_KEY="$(openssl rand -base64 32)"
```

**Important:** Keep the same encryption key when restarting the server with an existing database. Do not commit the key to GitHub.

Start the server:

```bash
go run main.go
```

The server runs on port **8080**.

## API Endpoints

- `POST /register` – Registers a new user and returns a generated password.
- `POST /auth` – Generates a signed JWT token and records the authentication request.
- `GET /.well-known/jwks.json` – Returns public RSA keys for JWT verification.

## Testing

I tested the project using Go unit tests covering encryption, registration, authentication, database operations, JWKS responses, and rate limiting.

To run the tests:

```bash
go test ./...
```

To check test coverage:

```bash
go test -coverprofile=coverage.out ./...
```

**Test coverage: 80.1%**

## Technologies Used

- Go
- SQLite
- AES-256-GCM
- RSA
- JWT
- Argon2id
- UUIDv4

## Conclusion

This project helped me understand how to improve application security by protecting private keys, securely storing passwords, tracking authentication activity, and testing security features.