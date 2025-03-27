package sqliteks

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// Database connection
var db *sql.DB

func Init() error {
	// SQLite database file (stored locally)
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "database.db" // Default SQLite file
	}

	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	// Create table if it doesn't exist
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		key_type TEXT NOT NULL,
		private_key TEXT NOT NULL,
		public_key TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	// Verify database connection
	err = db.Ping()
	return err
}

func Close() {
	if db != nil {
		db.Close()
	}
}

func AddKey(keyID *string, keyType *string, sk []byte, pk []byte) error {
	_, err := db.Exec(
		"INSERT INTO keys (id, key_type, private_key, public_key) VALUES (?, ?, ?, ?)",
		keyID,
		keyType,
		base64.StdEncoding.EncodeToString(sk),
		base64.StdEncoding.EncodeToString(pk),
	)
	return err
}

func GetPrivateKeyFromDB(keyID *string) ([]byte, []byte, string, error) {
	var base64Value, pkb64, keyType string
	err := db.QueryRow("SELECT private_key, public_key, key_type FROM keys WHERE id = ?", keyID).
		Scan(&base64Value, &pkb64, &keyType)
	if err != nil {
		return nil, nil, "", err
	}

	// Decode base64 private and public keys
	privateKeyBytes, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return nil, nil, "", err
	}
	publicKeyBytes, err := base64.StdEncoding.DecodeString(pkb64)
	if err != nil {
		return nil, nil, "", err
	}

	return privateKeyBytes, publicKeyBytes, keyType, nil
}

func Ping() error {
	return db.Ping()
}

