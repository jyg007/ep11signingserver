package postgresqlks

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// Database connection
var db *sql.DB

func Init() error {
	// PostgreSQL connection string
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)

	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		return err
	}

	err = db.Ping()
	if err != nil {
		return err
	}

	// Create table if it doesn't exist
	createTableQuery := `CREATE TABLE IF NOT EXISTS keys (
		id UUID PRIMARY KEY,
		key_type TEXT NOT NULL,
		private_key TEXT NOT NULL,
		public_key TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(createTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	return nil
}

func Close() {
	db.Close()
}

func AddKey(keyID *string, keyType *string, sk []byte, pk []byte) error {
	_, err := db.Exec("INSERT INTO keys (id, key_type, private_key, public_key) VALUES ($1, $2, $3, $4)",
		keyID, keyType, base64.StdEncoding.EncodeToString(sk), base64.StdEncoding.EncodeToString(pk))
	return err
}

func GetPrivateKeyFromDB(keyID *string) ([]byte, []byte, string, error) {
	var base64Value, pkb64, keyType string
	err := db.QueryRow("SELECT private_key, public_key, key_type FROM keys WHERE id = $1", keyID).
		Scan(&base64Value, &pkb64, &keyType)
	if err != nil {
		return nil, nil, "", err
	}

	// Decode base64 private key
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


