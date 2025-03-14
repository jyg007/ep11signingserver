## Simple Signing Server for IBM Crypto Express Card


## Features


## Installation

### Compiling

go mod init
go mod tidy
go build sigingserver.go


### Creating the mariadb key store



### Generating TLS certificates for the server

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

### 
