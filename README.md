# JWKS Server – Project 2

**CSCE 3550 – Foundations of Cybersecurity**

## About the Project

For this project, I extended my JWKS server using Go and SQLite. The server stores RSA private keys in a database, generates JWT tokens, and provides public keys for verification.

## Features

- Stores private keys using SQLite.
- Generates valid and expired JWTs.
- Provides public keys through the JWKS endpoint.
- Uses RSA encryption for signing tokens.

## How to Run

Run the following command in the terminal:

```bash
go run main.go
```

The server runs on port 8080.

## Testing

I tested the project using Go tests and the provided Gradebot.

- **Test coverage:** 82.7%
- **Gradebot score:** 98.21%

Screenshots of both results are included in the repository.