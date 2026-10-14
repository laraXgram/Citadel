<?php

use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\Http\Middleware\AuthenticateSession;
use LaraGram\Cookie\Middleware\EncryptCookies;
use LaraGram\Foundation\Http\Middleware\PreventRequestForgery;

return [

    /*
    |--------------------------------------------------------------------------
    | Stateful Domains
    |--------------------------------------------------------------------------
    |
    | Requests from the following domains / hosts will receive stateful API
    | authentication cookies. Typically, these should include your local
    | and production domains which access your API via a frontend SPA.
    |
    */

    'stateful' => explode(',', env('CITADEL_STATEFUL_DOMAINS', sprintf(
        '%s%s',
        'localhost,localhost:3000,127.0.0.1,127.0.0.1:8000,::1',
        Citadel::currentApplicationUrlWithPort(),
        // Citadel::currentRequestHost(),
    ))),

    /*
    |--------------------------------------------------------------------------
    | Stateful Guards
    |--------------------------------------------------------------------------
    |
    | These guards are checked before any token when Citadel authenticates a
    | request. Add Luna's "telegram" guard to authenticate Telegram Mini
    | App requests by their init data without issuing a token at all.
    |
    */

    'guard' => ['web'],

    /*
    |--------------------------------------------------------------------------
    | Default User Provider
    |--------------------------------------------------------------------------
    |
    | OAuth access tokens identify a user by their auth identifier (usually
    | the Telegram user id). When neither the guard nor the client names
    | a provider, users are resolved through the provider listed here.
    |
    */

    'provider' => env('CITADEL_PROVIDER', 'users'),

    /*
    |--------------------------------------------------------------------------
    | Personal Access Tokens
    |--------------------------------------------------------------------------
    |
    | "expiration" is the number of minutes a personal access token remains
    | valid, overriding the token's own "expires_at" value. The prefix is
    | prepended to new tokens so secret scanners can recognize them.
    |
    */

    'expiration' => null,

    'token_prefix' => env('CITADEL_TOKEN_PREFIX', ''),

    'last_used_at' => true,

    /*
    |--------------------------------------------------------------------------
    | SPA Middleware
    |--------------------------------------------------------------------------
    |
    | When authenticating your first-party SPA with Citadel you may need to
    | customize some of the middleware Citadel uses while processing the
    | request. You may change the middleware listed below as required.
    |
    */

    'middleware' => [
        'authenticate_session' => AuthenticateSession::class,
        'encrypt_cookies' => EncryptCookies::class,
        'validate_csrf_token' => PreventRequestForgery::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | OAuth2 Server
    |--------------------------------------------------------------------------
    |
    | "guard" is the stateful guard used to log users in on the authorization
    | screens. The RSA keys sign access tokens; they are read from storage
    | unless provided here (for example via environment variables).
    |
    */

    'oauth' => [

        'path' => env('CITADEL_OAUTH_PATH', 'oauth'),

        'middleware' => [],

        'guard' => 'web',

        'private_key' => env('CITADEL_PRIVATE_KEY'),

        'public_key' => env('CITADEL_PUBLIC_KEY'),

    ],

    /*
    |--------------------------------------------------------------------------
    | Database Connection
    |--------------------------------------------------------------------------
    |
    | By default, Citadel's models will utilize your application's default
    | database connection. If you wish to use a different connection you
    | may specify the configured name of the database connection here.
    |
    */

    'connection' => env('CITADEL_CONNECTION'),

    /*
    |--------------------------------------------------------------------------
    | Telegram
    |--------------------------------------------------------------------------
    |
    | Citadel verifies Telegram Mini App init data and Login Widget payloads
    | with the token of the bot connection named here (the default one when
    | null). "auth_ttl" is the maximum age of a payload in seconds.
    |
    | "scheme" selects how init data is verified: "hmac" (bot token),
    | "signature" (Telegram's Ed25519 public key) or "both".
    |
    */

    'telegram' => [

        'connection' => env('CITADEL_BOT_CONNECTION'),

        'auth_ttl' => (int) env('CITADEL_TELEGRAM_AUTH_TTL', 86400),

        'scheme' => env('CITADEL_TELEGRAM_SCHEME', 'hmac'),

        'test_env' => (bool) env('CITADEL_TELEGRAM_TEST_ENV', false),

        'public_keys' => [
            'production' => 'e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d',
            'test' => '40055058a4ee38156a06562e52eece92a771bcd8346a8c4615cb7376eddf72ec',
        ],

        'login_guard' => env('CITADEL_TELEGRAM_LOGIN_GUARD', 'web'),

        'home' => env('CITADEL_TELEGRAM_HOME', '/'),

        'device_approval' => (bool) env('CITADEL_TELEGRAM_DEVICE_APPROVAL', true),

    ],

];
