# VPNGen Partners API

## Terms

- __Brigadier__- is a VPN admin, who can create VPN users and manage their access to the VPN.
- __Brigade__ - is a brigadier's user group.
- __Brigadier__ is VPN user itself, but with access to keydesk.
- __Keydesk__ - is a Web UI for brigadier to manage brigade users.
- __Embassy__ - is a application, to communicate with the potential brigadierin the web, messengers, etc.

## Overview

API implements interface to embassies to communicate with the "ministry" server. The API implements the following futures:

* Create brigadier, brigadier VPN credentials and keydesk credentials.
* Recreate brigadier config: Not implemented yet
* Account recovery: Not implemented yet

## Public API

Uses swagger 2.0 for documentation and generation of server code

### Authentication

Bearer token in `Authorization` header (RFC 6750) should be provided for all requests.
Every external application ("embassy") should have its own token.

### Create Brigadier

* `POST /admin` without any parameters
* 201: Returns a set of credentials for the brigadier: 
```
 {
  "KeydeskIPv6Address": "string",
  "PersonDesc": "string",
  "PersonDescLink": "string",
  "PersonName": "string",
  "SeedMnemo": "string",
  "UserName": "string",
  "WireGuardConfig": "string",
  "WireGuardConfigName": "string"
 }
```
* 403: You do not have necessary permissions for the resource - if token is invalid or not provided 
`{"error": 403, "message": "unauthenticated for invalid credentials"}`
* 429: Rate limit reached for requests - if you have reached the limit of brigadiers (60 requests per hour)
`{"error": 429, "message": "rate limit reached for requests"}`
* 500:  Internal Server Error - if something went wrong
`{"error": 500, "message": "internal server error"}`
* Defult error response:
```
{
  "error": int,
  "message": "string"
}
```

### Limitations

60 requessts per hour per token. The server will return 429 error if the limit is reached.
The sliding window is 1 hour.

### Recreate Brigadier Config

Not implemented yet

### Account Recovery

Not implemented yet

## Server interaction

Upon successful authentication, the server connects to the "ministry" server using SSH to create a brigadier and obtain its credentials. SSH credentials are not covered in this document.

__NOTE:__ This is a temporary solution. It just for the legacy telegram embassy bot API calls support. The server will be rewritten and will be the part of the "ministry" server. It will use the "ministry" database directly.

## Tokens

### Abstract

Each token is a JWT token that includes a 'name' claim, with the token name being a random, human-readable string. JWT tokens use an HMAC 256 signature, but secret key management is not discussed in this document. Tokens are stored in a text file with one token per line. An optional list of allowed IP prefixes can be added to each line, separated by a comma. This list consists of comma-separated IP prefixes in CIDR notation or individual IP addresses, which are interpreted as /32 CIDR notation. The list is empty by default and is used to restrict token usage to specific IP prefixes. However, the prefix limitation feature is not yet implemented. The "ministry" server authenticates the embassy using the SHA-256 digest of the token.

### Generation

* Generate a token using the gentoken.sh script. This script creates a random token name and a JWT token with an HMAC 256 signature. The token name, token, and its SHA-256 digest base64url encoded are displayed on stdout and the token is saved to the `tokens` file.
* Add the token's SHA-256 digest base64url encoded and the token name to the ministry database. The hash serves to authenticate the embassy. The token name is used to identify the key.

## Monitoring

### Requests limit control

Dedicated HTTP-server for this kind of monitoring with separate port and address. The server is not exposed to the internet. It is only available from the service LAN. Server API: 

* `/metrics/embassy_integration_token?action=list&format=zabbix` - list of all tokens in zabbix format
* `/metrics/embassy_integration_token?action=request_count&token=<token>&format=zabbix` - number of requests for the token in zabbix format

__NOTE:__ There is no token in the list just mnemonics of the key pairs. The someone will use the mnemonic to find the token in the database if necessary.


## Agreements  

* If API server can't open x509 certificate, it won't handle HTTPS requests.
* If API server handle HTTPS request, it will redirect all HTTP requests to HTTPS.
* The API server listens on the port 8443 with self-signed certificate. 
* The API monitoring server listens on the port 8080 withouth TLS. The server is not exposed to the internet. It is only available from the service LAN.
* The SSH keys default type is ED25519.
* The limitations based on the sliding window of 1 hour.

## Implementation

* The API server is written in Go with go-swagger (swagger 2.0). Swagger file is located in `swagger/` directory.
* The limitation implemented with badger database.
  * The database is encrypted with AES.
  * Keys is the token sha256 digest concatenated with the hour, minute and second of the request time.
  * Keys are stored in the database with TTL equal 1 hour.
  * Request count calculated with prefix scan key-only iteration.
