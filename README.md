## Simple Signing Server for IBM Crypto Express Card


## Features


## Installation

### Compiling

go mod init
go mod tidy
go build sigingserver.go


### Creating the mariadb key store

#### installing the mariadb software on RHEL
dnf install mariadb-server
systemctl start mariadb

#### connecting 
> mysql -u root -p

CREATE USER 'john'@'localhost' IDENTIFIED BY 'SecureP@ssw0rd123';
CREATE DATABASE key_store;
USE key_store;
GRANT ALL PRIVILEGES ON key_store.* TO 'john'@'localhost';
CREATE TABLE `keys` (
         id VARCHAR(36) PRIMARY KEY,
         private_key TEXT NOT NULL,
         public_key TEXT NOT NULL,
         key_type VARCHAR(50) NOT NULL,
         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
     );


### Generating TLS certificates for the server

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

### Configuring the signing service

Create a .env file in the current directory to specify how to connect Mariadb and the API key to use to connect the service.

DB_USER=john
DB_PASSWORD=SecureP@ssw0rd123
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=key_store
API_KEY=mykey


## Testing the service

### Creating keys

curl -k --request POST \
  --url https://localhost:9443/signing/api/v2/keys?type=ECDSA_SECP256K1 \
  --header 'X-API-Key: mykey' \
  --header 'Content-Type: application/json'  

curl -k --request POST \
  --url https://localhost:9443/signing/api/v2/keys?type=ECDSA_BLS12 \
  --header 'X-API-Key: mykey' \
  --header 'Content-Type: application/json'
 
curl -k --request POST \
  --url https://localhost:9443/signing/api/v2/keys?type=EDDSA_ED25519 \
  --header 'X-API-Key: mykey' \
  --header 'Content-Type: application/json'

### Signing


### Verifying signature

Use the key id provided by the key creation call

curl  -k --request POST \
  --url https://localhost:9443/signing/api/v2/verify \
  --header 'Content-Type: application/json' \
  --data '{
         "id": "c83e9f36-eb0b-43ca-8d89-345eb4dcac40",
        "data" : "SGFsbG8gZGFzIGlzdCBlaW4gVGVzdA==",
        "signature" : "LjtkbKI7W/NQtlLKcm6+wZvx9mJAGoBz0eqDpk0rprp41WxCfIIgoNtIr6iRt37t/9gHPRn6Mrq23D9XuOxrLg=="
}'

