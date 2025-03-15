package main

/*
#cgo LDFLAGS: -lep11
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import (
	
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	 "strconv"
	//"bytes"
	"time"
    "encoding/asn1"

    "signingserver/ep11"

	"github.com/google/uuid"

	"github.com/joho/godotenv"
	_ "github.com/go-sql-driver/mysql"

	"database/sql"
)

var target ep11.Target_t 

// Database connection
var db *sql.DB

var apiKey string

// Response structure
type KeyResponse struct {
	ID     string `json:"id"`
	PubKey string `json:"pubKey"`
}

// SignRequest represents the JSON structure for signing requests
type SignRequest struct {
	Data string `json:"data"`
	ID   string `json:"id"`
}

// VerifyRequest represents the JSON structure for verifying signatures
type VerifyRequest struct {
	ID        string `json:"id"`        // UUID of the key
	Data      string `json:"data"`      // Base64-encoded data that was signed
	Signature string `json:"signature"` // Base64-encoded signature
}

// Middleware to check API key
func apiKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		
		key := r.Header.Get("X-API-Key")
		if key == "" || key != apiKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func getPrivateKeyFromDB(keyID string) ([]byte,[]byte, string, error) {
	var base64Value,pkb64, keyType string
	err := db.QueryRow("SELECT private_key, public_key, key_type FROM `keys` WHERE id = ?", keyID).Scan(&base64Value,&pkb64,&keyType)
	if err != nil {
		return nil, nil, "",err
	}

	// Decode base64 private key
	privateKeyBytes, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return nil, nil, "",err
	}
	publicKeyBytes, err := base64.StdEncoding.DecodeString(pkb64)
	if err != nil {
		return nil, nil, "",err
	}

	return privateKeyBytes, publicKeyBytes, keyType,nil
}


//*********************************************************************************************************
//*********************************************************************************************************
// Handler for key generation
//*********************************************************************************************************
//*********************************************************************************************************
func generateKeyHandler(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate query parameter
	keyType := r.URL.Query().Get("type")

	var publicKeyECTemplate ep11.Attributes
	var privateKeyECTemplate ep11.Attributes

	switch keyType {
	    case "ECDSA_SECP256K1": 
		    ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveSecp256k1)
		    if err != nil {
		            panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
		    }

		    publicKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_VERIFY:    true,
		    }
		    privateKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_SIGN:      true,
		            C.CKA_PRIVATE:   true,
		            C.CKA_SENSITIVE: true,
		    }
	    case "EDDSA_ED25519": 
		    ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveED25519)
		    if err != nil {
		            panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
		    }

		    publicKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_VERIFY:    true,
		    }
		    privateKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_SIGN:      true,
		            C.CKA_PRIVATE:   true,
		            C.CKA_SENSITIVE: true,
		    }
   	    case "ECDSA_BLS12": 
		    ecParameters, err := asn1.Marshal(ep11.OIDBLS12_381ET)
		    if err != nil {
		            panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
		    }

		    publicKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_VERIFY:    true,
		            C.CKA_IBM_USE_AS_DATA: true,
		            C.CKA_KEY_TYPE:        C.CKK_EC,
		    }
		    privateKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_SIGN:      true,
		            C.CKA_PRIVATE:   true,
		            C.CKA_SENSITIVE: true,
		            C.CKA_IBM_USE_AS_DATA: true,
		            C.CKA_KEY_TYPE:        C.CKK_EC,
		    }
		}

    pk, sk , err  := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_EC_KEY_PAIR_GEN, nil), publicKeyECTemplate,privateKeyECTemplate)

    if err != nil {
    			slog.Error("GenerateKeyPair error", "error", err)
    			http.Error(w, "Error Generating key pair", http.StatusInternalServerError)
    			return 

   	} 

	// Generate a UUID 
	var keyID string
	keyIDuuid , err := uuid.NewV7()
	if err != nil {
		slog.Error("Failed to generate UUIDv7","error",err)
		http.Error(w, "Failed to generate UUIDv7", http.StatusInternalServerError)
		return
	} else {
		keyID=keyIDuuid.String()
	}
	slog.Info("GenerateKeyPair " + keyID)


   // fmt.Printf("Private Key: %x\n\n",generateKeyPairResponse.PrivKeyBytes)
   	_, err = db.Exec("INSERT INTO `keys` (id, key_type, private_key, public_key) VALUES (?, ?, ?,?)", keyID, keyType, base64.StdEncoding.EncodeToString(sk),base64.StdEncoding.EncodeToString(pk))

   if err != nil {
 		slog.Error("Inserting key into db error","error",err)
 		http.Error(w, "Error when insertinf key in key store", http.StatusInternalServerError)
 		return
    }

	pubKeyBase64 := base64.StdEncoding.EncodeToString(pk)

	// Create response
	response := KeyResponse{
		ID:     keyID,
		PubKey: pubKeyBase64,	
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}


//*********************************************************************************************************
//*********************************************************************************************************
// Handler for multi keys generation
//*********************************************************************************************************
//*********************************************************************************************************
func signDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode request body
	var req SignRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	slog.Info("Signing with key " + req.ID)

	// Decode base64 data to bytes
	dataBytes, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		http.Error(w, "Invalid base64 data", http.StatusBadRequest)
		return
	}

	// Retrieve private key from database
	privateKeyBytes, _ , keyType, err := getPrivateKeyFromDB(req.ID)
	if err != nil {
		http.Error(w, "Private key not found", http.StatusNotFound)
		return
	}

	var mecha uint

	switch keyType {
	    case "ECDSA_SECP256K1": 
			  mecha = C.CKM_ECDSA
	    case "EDDSA_ED25519": 
	    	  mecha = C.CKM_IBM_ED25519_SHA512
	}

    sig, err := ep11.SignSingle(target, ep11.Mech(mecha,nil),privateKeyBytes,dataBytes)
	if err != nil {
		message := fmt.Sprintf("Error generating signature with key %s.", req.ID)
 		slog.Error(message,"error",err)
 		http.Error(w, message, http.StatusInternalServerError)
 		return
    }

    signatureBase64 := base64.StdEncoding.EncodeToString(sig)

	// Return signature as plain text
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(signatureBase64))
}

//*********************************************************************************************************
//*********************************************************************************************************
// Handler for multi keys generation
//*********************************************************************************************************
//*********************************************************************************************************
func verifySignatureHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode request body
	var req VerifyRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	slog.Info("Verifying with key " + req.ID)
	// Decode base64-encoded data
	dataBytes, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		http.Error(w, "Invalid base64 data", http.StatusBadRequest)
		return
	}

	// Decode base64-encoded signature
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "Invalid base64 signature", http.StatusBadRequest)
		return
	}

	// Retrieve private key from database
	_ , publicKeyBytes , keyType, err := getPrivateKeyFromDB(req.ID)
	
	if err != nil {
		http.Error(w, "Private key not found", http.StatusInternalServerError)
		return
	}

	var mecha uint

	switch keyType {
	    case "ECDSA_SECP256K1": 
			  mecha = C.CKM_ECDSA
	    case "EDDSA_ED25519": 
	    	 mecha = C.CKM_IBM_ED25519_SHA512
	}

    err = ep11.VerifySingle(target, ep11.Mech(mecha,nil),publicKeyBytes,dataBytes,sigBytes)

    if err != nil  {
    		message := fmt.Sprintf("Error verifying signature with key %s with return code %d", req.ID,err)
           	slog.Error(message,"error",err) 
           	http.Error(w, "Signature verification failed", http.StatusBadRequest)

    } else {
    	w.WriteHeader(http.StatusOK)
    }
}


//*********************************************************************************************************
//*********************************************************************************************************
// Handler for multi keys generation
//*********************************************************************************************************
//*********************************************************************************************************

func generateMultiKeyHandler(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate query parameter
	keyType := r.URL.Query().Get("type")
	keyNumber,_ := strconv.Atoi(r.URL.Query().Get("number"))

	var publicKeyECTemplate ep11.Attributes
	var privateKeyECTemplate ep11.Attributes


		switch keyType {
	    case "ECDSA_SECP256K1": 
		    ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveSecp256k1)
		    if err != nil {
		            panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
		    }

		    publicKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_VERIFY:    true,
		    }
		    privateKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_SIGN:      true,
		            C.CKA_PRIVATE:   true,
		            C.CKA_SENSITIVE: true,
		    }
	    case "EDDSA_ED25519": 
		    ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveED25519)
		    if err != nil {
		            panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
		    }

		    publicKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_VERIFY:    true,
		    }
		    privateKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_SIGN:      true,
		            C.CKA_PRIVATE:   true,
		            C.CKA_SENSITIVE: true,
		    }
   	    case "ECDSA_BLS12": 
		    ecParameters, err := asn1.Marshal(ep11.OIDBLS12_381ET)
		    if err != nil {
		            panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
		    }

		    publicKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_VERIFY:    true,
		            C.CKA_IBM_USE_AS_DATA: true,
		            C.CKA_KEY_TYPE:        C.CKK_EC,
		    }
		    privateKeyECTemplate = ep11.Attributes{
		            C.CKA_EC_PARAMS: ecParameters,
		            C.CKA_SIGN:      true,
		            C.CKA_PRIVATE:   true,
		            C.CKA_SENSITIVE: true,
		            C.CKA_IBM_USE_AS_DATA: true,
		            C.CKA_KEY_TYPE:        C.CKK_EC,
		    }
	}


	for i:=0;i<=keyNumber;i++ {  
	 
    	pk, sk , err  := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_EC_KEY_PAIR_GEN, nil), publicKeyECTemplate,privateKeyECTemplate)
    	if err != nil {

    			slog.Error("GenerateKeyPair error", "error", err)
    			return
    	} 

		// Generate a UUID 
		var keyID string
		keyIDuuid , err := uuid.NewV7()
		if err != nil {
			slog.Error("Failed to generate UUIDv7","error",err)
			return
		} else {
			keyID=keyIDuuid.String()
		}
		slog.Info("GenerateKeyPair " + keyID)

	   	_, err = db.Exec("INSERT INTO `keys` (id, key_type, private_key, public_key) VALUES (?, ?, ?,?)", keyID, keyType, base64.StdEncoding.EncodeToString(sk),base64.StdEncoding.EncodeToString(pk))

	   if err != nil {
	 		slog.Error("Inserting key into db error","error",err)
	 		return
	    }
	}
/*
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pk)

	// Create response
	response := KeyResponse{
		ID:     keyID,
		PubKey: pubKeyBase64,	
	}
*/
	// Send response
//	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)
}


//*********************************************************************************************************
//*********************************************************************************************************
// MAIN
//*********************************************************************************************************
//*********************************************************************************************************

func main() {

	// Load environment variables
	err := godotenv.Load()
	apiKey = os.Getenv("API_KEY")

	if err != nil {
		slog.Error("Error loading .env file")
		return
	}

	// MariaDB connection
	//socketPath := "/var/lib/mysql/mysql.sock" 
	  
/*
	dsn := fmt.Sprintf("%s:%s@unix(%s)/%s?parseTime=true",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		socketPath,
		os.Getenv("DB_NAME"),
	)
	*/
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		slog.Error("Failed to connect to database:", err)
	}
	defer db.Close()

	// Verify database connection
	err = db.Ping()
	if err != nil {
		slog.Error("Database connection failed:", err)
	}

	// Add your domain here - adapter number and domain number.
	// If multiple domain are added, make sure they have the same master key
	target = ep11.HsmInit(os.Getenv("HSM")) 

	rand.Seed(time.Now().UnixNano())

	// Check if TLS certs exist
	if _, err := os.Stat("cert.pem"); os.IsNotExist(err) {
		slog.Error("Missing TLS certificate (cert.pem). Run OpenSSL command to generate one.")
	}
	if _, err := os.Stat("key.pem"); os.IsNotExist(err) {
		slog.Error("Missing TLS private key (key.pem). Run OpenSSL command to generate one.")
	}

	// Setup HTTP routes
	http.HandleFunc("/signing/api/v2/keys", apiKeyMiddleware(generateKeyHandler))
	http.HandleFunc("/signing/api/v2/multikeys", apiKeyMiddleware(generateMultiKeyHandler))
	http.HandleFunc("/signing/api/v2/sign", apiKeyMiddleware(signDataHandler))
	http.HandleFunc("/signing/api/v2/verify", apiKeyMiddleware(verifySignatureHandler))

	// Start HTTPS server on port 9443
	slog.Info("Server running on https://localhost:9443")
	err = http.ListenAndServeTLS(":9443", "cert.pem", "key.pem", nil)
	if err != nil {
		slog.Error("Failed to start server", "error",err)
	}
}
