# Caddy replace_token

A Caddy v2 plugin that fetches a temporary token and replaces the original one in requests.

## Features

This plugin implements the http.handlers module, which:

- Uses the bearer token from request to fetch a temporary token from specified authentication server.

- Replaces the original token in request header, and pass to following handlers.

- Caches temporary tokens in memory and (optional) local storage.

## Configuration

```json
{
    "handler": "replace_token",
    "auth_url": "",
    "headers": {
        "": ""
    },
    "cache_file": ""
}
```
`headers` sets the headers of request to authentication server.

The authentication server should return a `token` and unix timestamp `expire_at` in the response body if succeeds.