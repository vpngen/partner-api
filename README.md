# VPNGen Partners API

## Terms

__Brigadier__- is a VPN admin, who can create VPN users and manage their access to the VPN.
__Brigade__ - is a brigadier's user group.
__Brigadier__ is VPN user itself, but with access to keydesk.
__Keydesk__ - is a Web UI for brigadier to manage brigade users.

## Overview

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

After successful authentication, the server calls "ministry" server via SSH to create brigadier and get brigadier credentials. SSH credentials for the call correspond to the token.

__NOTE:__ This is a temporary solution. It just for the legacy telegram embassy bot API calls support. The server will be rewritten and will be the part of the "ministry" server. It will use the "ministry" database directly.

## SSH credentials and tokens

### Abstract

Every token corresponds to a SSH key pair. The name of the key pair constructed from the classic name of the ssh key files and some random unique mnemonic string dot separated. For example, `id_ed25519.nameone` and `id_ed25519.nametwo` are two different key pairs. The comment field of the secret key is a magic string. Format of the magic string is `;sha256-hash;net-list`. SHA256 hash is a hash of token. Net-list is a list of networks in CIDR format, separated by commas. For example, `;DmffaxnxNqKy+Y3GruMh60HkdPJSuESYYmnVCp7c/2U=;0.0.0.0/0` is a magic string for the token `5q19sxL9JTg9xnAA4GyloNLjVZbsUgpPZdpCqKN5mIo=`. The server will allow SSH connections only from the networks in the net-list (not implemented yet). The "ministry" server uses public key sha256 hash to authenticate the request.

### Generation

* Create a key pair with `genkey.sh` script. The script generates a key pair, token and magic string.
* Add the public key to the `authorized_keys` file on the "ministry" server.
* Add the sha256 hash of the public key and the mnemonic to the database on the "ministry" server.
* The mnemonic of the key pair must be same as in the "ministry" database.
 
## Monitoring

### Request limits control

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
  * Keys are stored in the database with TTL equal 1 hour.
  * Request count calculated with prefix scan key-only iteration.
