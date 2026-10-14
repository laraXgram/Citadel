<h1 align="center">LaraGram Citadel</h1>

<p align="center">API authentication for LaraGram: personal access tokens, SPA sessions and a complete OAuth2 server, with Telegram sign-in built in.</p>

---

Citadel merges Laravel Sanctum and Laravel Passport into one package with **one guard** (`auth:citadel`) and **one trait** (`HasApiTokens`):

| Feature | What it does |
| --- | --- |
| **Personal access tokens** | `$user->createToken('cli', ['orders:read'])`, abilities, expiry, last-used tracking. |
| **SPA & Mini App sessions** | First-party SPAs use the session; Luna Telegram Mini Apps use Luna's `telegram` guard, with no tokens at all. |
| **OAuth2 server** | Authorization code + PKCE, client credentials, refresh token rotation, device flow (RFC 8628), revocation (RFC 7009) and server metadata (RFC 8414), on a native engine with no third-party dependencies. |
| **Telegram grants** | Exchange Mini App init data or Login Widget data for OAuth tokens. |
| **Bot approvals** | Users approve devices (CLIs, MCP clients) and issue tokens right in the bot. |

```bash
composer require laraxgram/citadel
php laragram citadel:install
```

Read the full documentation at [laraxgram.github.io](https://laraxgram.github.io/v4/citadel).

## License

LaraGram Citadel is open-sourced software licensed under the [MIT license](LICENSE.md). It is based on Laravel Sanctum and Laravel Passport by Taylor Otwell.
