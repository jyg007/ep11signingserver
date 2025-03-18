package postgresks

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Database connection pool
var db *pgxpool.Pool

func Init() error {
	// PostgreSQL connection string
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)

	var err error
	db, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}

	// Create table if it doesn't exist
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		key_type TEXT NOT NULL,
		private_key TEXT NOT NULL,
		public_key TEXT NOT NULL
	);
	`
	_, err = db.Exec(context.Background(), createTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	return nil
}

func Close() {
	if db != nil {
		db.Close()
	}
}

func AddKey(keyID *string, keyType *string, sk []byte, pk []byte) error {
	_, err := db.Exec(
		context.Background(),
		"INSERT INTO keys (id, key_type, private_key, public_key) VALUES ($1, $2, $3, $4)",
		keyID,
		keyType,
		base64.StdEncoding.EncodeToString(sk),
		base64.StdEncoding.EncodeToString(pk),
	)
	return err
}
