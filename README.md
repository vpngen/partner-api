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

### Recreate Brigadier Config

Not implemented yet

### Account Recovery

Not implemented yet

## Server interaction

After successful authentication, the server calls "ministry" server via SSH to create brigadier and get brigadier credentials. SSH credentials for the call correspond to the token.

## SSH credentials and tokens

Every token corresponds to a SSH key pair. The name of the key pair constructed from the classic name of the ssh key files and some random mnemonic string dot separated. For example, `id_ed25519.nameone` and `id_ed25519.nametwo` are two different key pairs. The comment field of the secret key is a magic string. Format of the magic string is `;sha256-hash;net-list`. SHA256 hash is a hash of token. Net-list is a list of networks in CIDR format, separated by commas. For example, `;DmffaxnxNqKy+Y3GruMh60HkdPJSuESYYmnVCp7c/2U=;0.0.0.0/0` is a magic string for the token `5q19sxL9JTg9xnAA4GyloNLjVZbsUgpPZdpCqKN5mIo=`. The server will allow SSH connections only from the networks in the net-list (not implemented yet). The "ministry" server uses public key sha256 hash to authenticate the request.

The `genkey.sh` script generates a key pair and prints the magic string. The `genkey.sh` script is used to generate SSH credentials and tokens.