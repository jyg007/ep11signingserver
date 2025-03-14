## Simple Signing Server for IBM Crypto Express Card

## Features

Basic API Gateway to create Secp256k1, Ed25519 key pair, and Sign data and Verify signature.  
Mariadb is provided as key store.

HSM Domain have to be specified in server.go code.  See ep11.hsminit() call.
Multple domains can be specified for high-availability or scalability.

## Running the server

Follow installation instruction.  Start mariadb as a service.

```bash
[root@hyprh3a ep11signingserver]# ./server 
2025/03/14 13:35:02 INFO Server running on https://localhost:9443
2025/03/14 13:35:06 INFO GenerateKeyPair 019595b9-5657-776b-86d6-923f74bf856e
2025/03/14 13:35:07 INFO GenerateKeyPair 019595b9-5aa3-76ac-8529-acfb4af72b68
```

## Installation

### Compiling

go mod init
go mod tidy
go build sigingserver.go

### Creating the mariadb key store

#### installing the mariadb software on RHEL

```bash
dnf install mariadb-server
systemctl start mariadb
```

#### connecting 
```bash
> mysql -u root -p
```
```sql
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
```

### Generating TLS certificates for the server
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```
### Configuring the signing service

Create a .env file in the current directory to specify how to connect Mariadb and the API key to use to connect the service.
```
DB_USER=john
DB_PASSWORD=SecureP@ssw0rd123
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=key_store
API_KEY=mykey
```

## Testing the service

### Creating keys
```bash
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
```
### Signing

```
$ curl -ik --request POST   --url 'https://localhost:9443/signing/api/v2/keys?type=ECDSA_SECP256K1'   --header 'X-API-Key: mykey'   --header 'Content-Type: application/json' 
HTTP/2 200 
content-type: application/json
content-length: 346
date: Fri, 14 Mar 2025 17:42:38 GMT

{"id":"019595c0-3b01-7326-a82a-9bf28d88369b","pubKey":"MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEx7FZrKZGXl0ZLWniqzoEzNfngaheJ3wsFzmHUMbeddmTxA+dJ50/xd9w8/s6egFIwKWmBsctZkZ5QbMKPVSM1wQQUNlMc/vzE30iOfEyGRAmpQQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAGD8fPXuoDxBAgAAAAAAAAAAQQUEAEAAAAAgCQAAIAkgAEACgAAAAEEIBR2S6pmmG4arzn6fzAAmmVpm3sgRaJE6oarrTXV0/99"}


$ curl -k --request POST \
  --url https://localhost:9443/signing/api/v2/sign \
  --header 'X-API-Key: mykey' \
  --header 'Content-Type: application/json' \
  --data '{
        "id": "019595c0-3b01-7326-a82a-9bf28d88369b",
        "data" : "SGVsbG8gV29ybGQga2luZCBvZiB0ZXN0Cg=="
}'
DZ6QPx1F5eqPGjHp9LDGFRXcnBoVHzhrYB3gvprvwV0y1o+3tOpME0+2LvM0CBUTlEPLcH3dnQXzmwMj4gVztg==
```

### Verifying signature

Use the key id provided by the key creation call
```bash
curl  -k --request POST \
  --url https://localhost:9443/signing/api/v2/verify \
  --header 'Content-Type: application/json' \
  --data '{
         "id": "c83e9f36-eb0b-43ca-8d89-345eb4dcac40",
        "data" : "SGFsbG8gZGFzIGlzdCBlaW4gVGVzdA==",
        "signature" : "LjtkbKI7W/NQtlLKcm6+wZvx9mJAGoBz0eqDpk0rprp41WxCfIIgoNtIr6iRt37t/9gHPRn6Mrq23D9XuOxrLg=="
}'

curl -ik --request POST   --url https://localhost:9443/signing/api/v2/verify   --header 'X-API-Key: mykey'   --header 'Content-Type: application/json'   --data '{
        "id": "019595c0-3b01-7326-a82a-9bf28d88369b",
        "data" : "SGVsbG8gV29ybGQga2luZCBvZiB0ZXN0Cg==",
        "signature": "DZ6QPx1F5eqPGjHp9LDGFRXcnBoVHzhrYB3gvprvwV0y1o+3tOpME0+2LvM0CBUTlEPLcH3dnQXzmwMj4gVztg=="
}'
HTTP/2 200 
content-length: 0
date: Fri, 14 Mar 2025 17:47:55 GMT

[root@hyprh3a ep11go]# curl -ik --request POST   --url https://localhost:9443/signing/api/v2/verify   --header 'X-API-Key: mykey'   --header 'Content-Type: application/json'   --data '{
        "id": "019595c0-3b01-7326-a82a-9bf28d88369b",
        "data" : "YmFsYmxhYmxhYmwK",
        "signature": "DZ6QPx1F5eqPGjHp9LDGFRXcnBoVHzhrYB3gvprvwV0y1o+3tOpME0+2LvM0CBUTlEPLcH3dnQXzmwMj4gVztg=="
}'
HTTP/2 400 
content-type: text/plain; charset=utf-8
x-content-type-options: nosniff
content-length: 30
date: Fri, 14 Mar 2025 17:48:09 GMT

Signature verification failed

```
