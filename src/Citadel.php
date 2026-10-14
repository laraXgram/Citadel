<?php

namespace LaraGram\Citadel;

use Closure;
use DateInterval;
use DateTimeInterface;
use LaraGram\Citadel\Contracts\AuthorizationViewResponse;
use LaraGram\Citadel\Contracts\DeviceAuthorizationViewResponse;
use LaraGram\Citadel\Contracts\DeviceUserCodeViewResponse;
use LaraGram\Citadel\Contracts\HasAbilities;
use LaraGram\Citadel\Http\Responses\SimpleViewResponse;
use LaraGram\Citadel\OAuth\ResourceServer;
use LaraGram\Contracts\Auth\Authenticatable;
use LaraGram\Contracts\Auth\UserProvider;
use LaraGram\Contracts\Encryption\Encrypter;
use LaraGram\Http\Request;
use LaraGram\Support\Collection;
use LaraGram\Support\Facades\Date;

class Citadel
{
    /**
     * The personal access token model class name.
     *
     * @var class-string<\LaraGram\Citadel\PersonalAccessToken>
     */
    public static string $personalAccessTokenModel = PersonalAccessToken::class;

    /**
     * A callback that can get the token from the request.
     *
     * @var (callable(\LaraGram\Http\Request): ?string)|null
     */
    public static $accessTokenRetrievalCallback;

    /**
     * A callback that can add to the validation of the personal access token.
     *
     * @var (callable(\LaraGram\Citadel\PersonalAccessToken, bool): bool)|null
     */
    public static $accessTokenAuthenticationCallback;

    /**
     * The placeholder replaced by the current request host in the stateful domains.
     */
    public static string $currentRequestHostPlaceholder = '__CITADEL_CURRENT_REQUEST_HOST__';

    /**
     * Indicates if Citadel should validate the permissions of its encryption keys.
     */
    public static bool $validateKeyPermissions = true;

    /**
     * Indicates if Citadel should revoke a refresh token after it was used.
     */
    public static bool $revokeRefreshTokenAfterUse = true;

    /**
     * Indicates if the device authorization grant is enabled.
     */
    public static bool $deviceCodeGrantEnabled = true;

    /**
     * Indicates if the implicit grant type is enabled.
     */
    public static bool $implicitGrantEnabled = false;

    /**
     * Indicates if the password grant type is enabled.
     */
    public static bool $passwordGrantEnabled = false;

    /**
     * Indicates if the Telegram grants (Mini App init data and Login Widget) are enabled.
     */
    public static bool $telegramGrantEnabled = true;

    /**
     * The default scope.
     */
    public static string $defaultScope = '';

    /**
     * All of the scopes defined for the application.
     *
     * @var array<string, string>
     */
    public static array $scopes = [
        //
    ];

    /**
     * The interval when access tokens expire.
     */
    public static ?DateInterval $tokensExpireIn = null;

    /**
     * The date when refresh tokens expire.
     */
    public static ?DateInterval $refreshTokensExpireIn = null;

    /**
     * The interval when client credentials tokens expire.
     */
    public static ?DateInterval $clientCredentialsTokensExpireIn = null;

    /**
     * The name for API token cookies.
     */
    public static string $cookie = 'laragram_token';

    /**
     * Indicates if Citadel should ignore incoming CSRF tokens on the API token cookie.
     */
    public static bool $ignoreCsrfToken = false;

    /**
     * The storage location of the encryption keys.
     */
    public static ?string $keyPath = null;

    /**
     * The auth code model class name.
     *
     * @var class-string<\LaraGram\Citadel\AuthCode>
     */
    public static string $authCodeModel = AuthCode::class;

    /**
     * The device code model class name.
     *
     * @var class-string<\LaraGram\Citadel\DeviceCode>
     */
    public static string $deviceCodeModel = DeviceCode::class;

    /**
     * The client model class name.
     *
     * @var class-string<\LaraGram\Citadel\Client>
     */
    public static string $clientModel = Client::class;

    /**
     * Indicates if clients are identified by UUIDs.
     */
    public static bool $clientUuids = true;

    /**
     * The OAuth access token model class name.
     *
     * @var class-string<\LaraGram\Citadel\Token>
     */
    public static string $tokenModel = Token::class;

    /**
     * The refresh token model class name.
     *
     * @var class-string<\LaraGram\Citadel\RefreshToken>
     */
    public static string $refreshTokenModel = RefreshToken::class;

    /**
     * Indicates if Citadel should unserialize cookies.
     */
    public static bool $unserializesCookies = false;

    /**
     * Indicates if Citadel should decrypt cookies.
     */
    public static bool $decryptsCookies = true;

    /**
     * The callback that should be used to generate the token encryption key.
     *
     * @var (\Closure(\LaraGram\Contracts\Encryption\Encrypter): string)|null
     */
    public static ?Closure $tokenEncryptionKeyCallback = null;

    /**
     * Indicates if scopes and abilities should be inherited ("orders" grants "orders:read").
     */
    public static bool $withInheritedScopes = false;

    /**
     * The class used to build the bearer token response of the token endpoint.
     *
     * @var class-string<\LaraGram\Citadel\OAuth\BearerTokenResponse>
     */
    public static string $bearerTokenResponse = OAuth\BearerTokenResponse::class;

    /**
     * Indicates if Citadel routes will be registered.
     */
    public static bool $registersRoutes = true;

    /**
     * Indicates if the JSON API routes (clients, tokens, scopes) will be registered.
     */
    public static bool $registersJsonApiRoutes = false;

    /**
     * Indicates if the authorization server metadata route (RFC 8414) will be registered.
     */
    public static bool $registersMetadataRoute = false;

    /**
     * The callbacks that extend the authorization server metadata.
     *
     * @var array<int, \Closure(array<string, mixed>): array<string, mixed>>
     */
    public static array $metadataExtenders = [];

    /**
     * The callback that resolves (or creates) the user for a verified Telegram identity.
     *
     * @var (\Closure(\LaraGram\Citadel\Telegram\TelegramIdentity, \LaraGram\Contracts\Auth\UserProvider): ?\LaraGram\Contracts\Auth\Authenticatable)|null
     */
    public static ?Closure $telegramUserResolver = null;

    /**
     * Get the current application URL from the "APP_URL" environment variable - with port.
     */
    public static function currentApplicationUrlWithPort(): string
    {
        $appUrl = config('app.url');

        return $appUrl ? ','.parse_url($appUrl, PHP_URL_HOST).(parse_url($appUrl, PHP_URL_PORT) ? ':'.parse_url($appUrl, PHP_URL_PORT) : '') : '';
    }

    /**
     * Get the current request host placeholder for the stateful domains.
     */
    public static function currentRequestHost(): string
    {
        return ','.static::$currentRequestHostPlaceholder;
    }

    /**
     * Enable the implicit grant type.
     */
    public static function enableImplicitGrant(): void
    {
        static::$implicitGrantEnabled = true;
    }

    /**
     * Enable the password grant type.
     */
    public static function enablePasswordGrant(): void
    {
        static::$passwordGrantEnabled = true;
    }

    /**
     * Disable the device authorization grant type.
     */
    public static function disableDeviceCodeGrant(): void
    {
        static::$deviceCodeGrantEnabled = false;
    }

    /**
     * Disable the Telegram grant types.
     */
    public static function disableTelegramGrant(): void
    {
        static::$telegramGrantEnabled = false;
    }

    /**
     * Set the default scope(s). Multiple scopes may be an array or specified delimited by spaces.
     *
     * @param  string[]|string  $scope
     */
    public static function setDefaultScope(array|string $scope): void
    {
        static::$defaultScope = is_array($scope) ? implode(' ', $scope) : $scope;
    }

    /**
     * Get or set the default scopes.
     *
     * @param  string[]|string|null  $scopes
     * @return string[]
     */
    public static function defaultScopes(array|string|null $scopes = null): array
    {
        if (! is_null($scopes)) {
            static::$defaultScope = is_array($scopes) ? implode(' ', $scopes) : $scopes;
        }

        return static::$defaultScope ? explode(' ', static::$defaultScope) : [];
    }

    /**
     * Return the scopes in the given list that are actually defined scopes for the application.
     *
     * @param  string[]  $scopes
     * @return string[]
     */
    public static function validScopes(array $scopes): array
    {
        return array_values(array_unique(array_intersect($scopes, array_keys(static::$scopes))));
    }

    /**
     * Get all of the defined scope IDs.
     *
     * @return string[]
     */
    public static function scopeIds(): array
    {
        return static::scopes()->pluck('id')->values()->all();
    }

    /**
     * Determine if the given scope has been defined.
     */
    public static function hasScope(string $id): bool
    {
        return $id === '*' || array_key_exists($id, static::$scopes);
    }

    /**
     * Get all of the scopes defined for the application.
     *
     * @return \LaraGram\Support\Collection<int, \LaraGram\Citadel\Scope>
     */
    public static function scopes(): Collection
    {
        return collect(static::$scopes)->map(
            fn (string $description, string $id): Scope => new Scope($id, $description)
        )->values();
    }

    /**
     * Get all of the scopes matching the given IDs.
     *
     * @param  string[]  $ids
     * @return \LaraGram\Citadel\Scope[]
     */
    public static function scopesFor(array $ids): array
    {
        return collect($ids)->map(
            fn (string $id): ?Scope => isset(static::$scopes[$id]) ? new Scope($id, static::$scopes[$id]) : null
        )->filter()->values()->all();
    }

    /**
     * Define the scopes for the application.
     *
     * @param  array<string, string>  $scopes
     */
    public static function tokensCan(array $scopes): void
    {
        static::$scopes = $scopes;
    }

    /**
     * Get or set when access tokens expire.
     */
    public static function tokensExpireIn(DateTimeInterface|DateInterval|null $date = null): DateInterval
    {
        if (is_null($date)) {
            return static::$tokensExpireIn ??= new DateInterval('P1Y');
        }

        return static::$tokensExpireIn = $date instanceof DateTimeInterface
            ? Date::now()->diff($date)
            : $date;
    }

    /**
     * Get or set when refresh tokens expire.
     */
    public static function refreshTokensExpireIn(DateTimeInterface|DateInterval|null $date = null): DateInterval
    {
        if (is_null($date)) {
            return static::$refreshTokensExpireIn ??= new DateInterval('P1Y');
        }

        return static::$refreshTokensExpireIn = $date instanceof DateTimeInterface
            ? Date::now()->diff($date)
            : $date;
    }

    /**
     * Get or set when client credentials tokens expire.
     */
    public static function clientCredentialsTokensExpireIn(DateTimeInterface|DateInterval|null $date = null): DateInterval
    {
        if (is_null($date)) {
            return static::$clientCredentialsTokensExpireIn ?? static::tokensExpireIn();
        }

        return static::$clientCredentialsTokensExpireIn = $date instanceof DateTimeInterface
            ? Date::now()->diff($date)
            : $date;
    }

    /**
     * Get or set the name for API token cookies.
     */
    public static function cookie(?string $cookie = null): string
    {
        if (is_null($cookie)) {
            return static::$cookie;
        }

        return static::$cookie = $cookie;
    }

    /**
     * Indicate that Citadel should ignore the CSRF token on the API token cookie.
     */
    public static function ignoreCsrfToken(bool $ignoreCsrfToken = true): void
    {
        static::$ignoreCsrfToken = $ignoreCsrfToken;
    }

    /**
     * Set the current user for the application with the given abilities (or scopes).
     *
     * @template TUser of \LaraGram\Contracts\Auth\Authenticatable
     *
     * @param  TUser  $user
     * @param  string[]  $abilities
     * @return TUser
     */
    public static function actingAs(Authenticatable $user, array $abilities = [], ?string $guard = 'citadel', ?Client $client = null): Authenticatable
    {
        $token = new AccessToken([
            'oauth_client_id' => $client?->getKey(),
            'oauth_user_id' => $user->getAuthIdentifier(),
            'oauth_scopes' => $abilities,
        ]);

        $user->withAccessToken($token);

        if (isset($user->wasRecentlyCreated) && $user->wasRecentlyCreated) {
            $user->wasRecentlyCreated = false;
        }

        app('auth')->guard($guard)->setUser($user);

        app('auth')->shouldUse($guard);

        return $user;
    }

    /**
     * Set the current client for the application with the given scopes.
     */
    public static function actingAsClient(Client $client, array $scopes = [], ?string $guard = 'citadel'): Client
    {
        app()->instance(ResourceServer::class, new class($client, $scopes) extends ResourceServer
        {
            public function __construct(protected Client $client, protected array $scopes)
            {
                //
            }

            public function validateAuthenticatedRequest(Request $request): array
            {
                return [
                    'oauth_access_token_id' => null,
                    'oauth_client_id' => $this->client->getKey(),
                    'oauth_user_id' => null,
                    'oauth_scopes' => $this->scopes,
                ];
            }
        });

        app('auth')->guard($guard)->setClient($client);

        app('auth')->shouldUse($guard);

        return $client;
    }

    /**
     * Get the access token of the user authenticated by the given (or default) guard.
     */
    public static function currentAccessToken(?string $guard = null): ?HasAbilities
    {
        $user = app('auth')->guard($guard)->user();

        return $user && method_exists($user, 'currentAccessToken') ? $user->currentAccessToken() : null;
    }

    /**
     * Determine if the current access token grants the given ability, failing closed.
     */
    public static function tokenCan(string $ability, ?string $guard = null): bool
    {
        return static::currentAccessToken($guard)?->can($ability) ?? false;
    }

    /**
     * Set the storage location of the encryption keys.
     */
    public static function loadKeysFrom(string $path): void
    {
        static::$keyPath = $path;
    }

    /**
     * The location of the encryption keys.
     */
    public static function keyPath(string $file): string
    {
        $file = ltrim($file, '/\\');

        return isset(static::$keyPath)
            ? rtrim(static::$keyPath, '/\\').DIRECTORY_SEPARATOR.$file
            : storage_path($file);
    }

    /**
     * Set the personal access token model name.
     *
     * @param  class-string<\LaraGram\Citadel\PersonalAccessToken>  $model
     */
    public static function usePersonalAccessTokenModel(string $model): void
    {
        static::$personalAccessTokenModel = $model;
    }

    /**
     * Get the personal access token model class name.
     *
     * @return class-string<\LaraGram\Citadel\PersonalAccessToken>
     */
    public static function personalAccessTokenModel(): string
    {
        return static::$personalAccessTokenModel;
    }

    /**
     * Specify a callback that should be used to fetch the access token from the request.
     */
    public static function getAccessTokenFromRequestUsing(?callable $callback): void
    {
        static::$accessTokenRetrievalCallback = $callback;
    }

    /**
     * Specify a callback that should be used to authenticate personal access tokens.
     */
    public static function authenticateAccessTokensUsing(?callable $callback): void
    {
        static::$accessTokenAuthenticationCallback = $callback;
    }

    /**
     * Set the auth code model class name.
     *
     * @param  class-string<\LaraGram\Citadel\AuthCode>  $authCodeModel
     */
    public static function useAuthCodeModel(string $authCodeModel): void
    {
        static::$authCodeModel = $authCodeModel;
    }

    /**
     * Get the auth code model class name.
     *
     * @return class-string<\LaraGram\Citadel\AuthCode>
     */
    public static function authCodeModel(): string
    {
        return static::$authCodeModel;
    }

    /**
     * Get a new auth code model instance.
     */
    public static function authCode(): AuthCode
    {
        return new static::$authCodeModel;
    }

    /**
     * Set the device code model class name.
     *
     * @param  class-string<\LaraGram\Citadel\DeviceCode>  $deviceCodeModel
     */
    public static function useDeviceCodeModel(string $deviceCodeModel): void
    {
        static::$deviceCodeModel = $deviceCodeModel;
    }

    /**
     * Get the device code model class name.
     *
     * @return class-string<\LaraGram\Citadel\DeviceCode>
     */
    public static function deviceCodeModel(): string
    {
        return static::$deviceCodeModel;
    }

    /**
     * Get a new device code model instance.
     */
    public static function deviceCode(): DeviceCode
    {
        return new static::$deviceCodeModel;
    }

    /**
     * Set the client model class name.
     *
     * @param  class-string<\LaraGram\Citadel\Client>  $clientModel
     */
    public static function useClientModel(string $clientModel): void
    {
        static::$clientModel = $clientModel;
    }

    /**
     * Get the client model class name.
     *
     * @return class-string<\LaraGram\Citadel\Client>
     */
    public static function clientModel(): string
    {
        return static::$clientModel;
    }

    /**
     * Get a new client model instance.
     */
    public static function client(): Client
    {
        return new static::$clientModel;
    }

    /**
     * Set the OAuth access token model class name.
     *
     * @param  class-string<\LaraGram\Citadel\Token>  $tokenModel
     */
    public static function useTokenModel(string $tokenModel): void
    {
        static::$tokenModel = $tokenModel;
    }

    /**
     * Get the OAuth access token model class name.
     *
     * @return class-string<\LaraGram\Citadel\Token>
     */
    public static function tokenModel(): string
    {
        return static::$tokenModel;
    }

    /**
     * Get a new OAuth access token model instance.
     */
    public static function token(): Token
    {
        return new static::$tokenModel;
    }

    /**
     * Set the refresh token model class name.
     *
     * @param  class-string<\LaraGram\Citadel\RefreshToken>  $refreshTokenModel
     */
    public static function useRefreshTokenModel(string $refreshTokenModel): void
    {
        static::$refreshTokenModel = $refreshTokenModel;
    }

    /**
     * Get the refresh token model class name.
     *
     * @return class-string<\LaraGram\Citadel\RefreshToken>
     */
    public static function refreshTokenModel(): string
    {
        return static::$refreshTokenModel;
    }

    /**
     * Get a new refresh token model instance.
     */
    public static function refreshToken(): RefreshToken
    {
        return new static::$refreshTokenModel;
    }

    /**
     * Specify the bearer token response class of the token endpoint.
     *
     * @param  class-string<\LaraGram\Citadel\OAuth\BearerTokenResponse>  $class
     */
    public static function useBearerTokenResponse(string $class): void
    {
        static::$bearerTokenResponse = $class;
    }

    /**
     * Specify the callback that should be invoked to generate encryption keys for encrypting OAuth codes and refresh tokens.
     *
     * @param  (\Closure(\LaraGram\Contracts\Encryption\Encrypter): string)|null  $callback
     */
    public static function encryptTokensUsing(?Closure $callback): void
    {
        static::$tokenEncryptionKeyCallback = $callback;
    }

    /**
     * Generate an encryption key for encrypting OAuth codes, refresh tokens and API token cookies.
     */
    public static function tokenEncryptionKey(Encrypter $encrypter): string
    {
        return is_callable(static::$tokenEncryptionKeyCallback)
            ? (static::$tokenEncryptionKeyCallback)($encrypter)
            : $encrypter->getKey();
    }

    /**
     * Specify how a verified Telegram identity is turned into a user (for example, by registering it).
     *
     * @param  (\Closure(\LaraGram\Citadel\Telegram\TelegramIdentity, \LaraGram\Contracts\Auth\UserProvider): ?\LaraGram\Contracts\Auth\Authenticatable)|null  $callback
     */
    public static function resolveTelegramUsersUsing(?Closure $callback): void
    {
        static::$telegramUserResolver = $callback;
    }

    /**
     * Resolve the user of a verified Telegram identity through the given provider.
     */
    public static function resolveTelegramUser(Telegram\TelegramIdentity $identity, UserProvider $provider): ?Authenticatable
    {
        if (static::$telegramUserResolver) {
            return (static::$telegramUserResolver)($identity, $provider);
        }

        return $provider->retrieveByUserId($identity->id);
    }

    /**
     * Register the views for Citadel using conventional names under the given namespace.
     */
    public static function viewNamespace(string $namespace): void
    {
        static::viewPrefix($namespace.'::');
    }

    /**
     * Register the views for Citadel using conventional names under the given prefix.
     */
    public static function viewPrefix(string $prefix): void
    {
        $prefix = rtrim($prefix, '.');

        static::authorizationView($prefix.'.authorize');
        static::deviceAuthorizationView($prefix.'.device.authorize');
        static::deviceUserCodeView($prefix.'.device.user-code');
    }

    /**
     * Specify which view should be used as the authorization view.
     *
     * @param  (\Closure(array<string, mixed>): (\LaraGram\Contracts\Support\Responsable|\LaraGram\Http\BaseResponse))|string  $view
     */
    public static function authorizationView(Closure|string $view): void
    {
        app()->singleton(AuthorizationViewResponse::class, fn () => new SimpleViewResponse($view));
    }

    /**
     * Specify which view should be used as the device authorization view.
     *
     * @param  (\Closure(array<string, mixed>): (\LaraGram\Contracts\Support\Responsable|\LaraGram\Http\BaseResponse))|string  $view
     */
    public static function deviceAuthorizationView(Closure|string $view): void
    {
        app()->singleton(DeviceAuthorizationViewResponse::class, fn () => new SimpleViewResponse($view));
    }

    /**
     * Specify which view should be used as the device user code view.
     *
     * @param  (\Closure(array<string, mixed>): (\LaraGram\Contracts\Support\Responsable|\LaraGram\Http\BaseResponse))|string  $view
     */
    public static function deviceUserCodeView(Closure|string $view): void
    {
        app()->singleton(DeviceUserCodeViewResponse::class, fn () => new SimpleViewResponse($view));
    }

    /**
     * Configure Citadel to not register its routes.
     */
    public static function ignoreRoutes(): void
    {
        static::$registersRoutes = false;
    }

    /**
     * Register the JSON API routes for managing clients and tokens.
     */
    public static function withJsonApiRoutes(): void
    {
        static::$registersJsonApiRoutes = true;
    }

    /**
     * Register the "/.well-known/oauth-authorization-server" metadata route.
     */
    public static function withAuthorizationServerMetadata(): void
    {
        static::$registersMetadataRoute = true;
    }

    /**
     * Add values to the authorization server metadata (for example a registration endpoint).
     *
     * @param  \Closure(array<string, mixed>): array<string, mixed>  $callback
     */
    public static function extendAuthorizationServerMetadata(Closure $callback): void
    {
        static::$metadataExtenders[] = $callback;
    }

    /**
     * Get the authorization server metadata (RFC 8414).
     *
     * @return array<string, mixed>
     */
    public static function authorizationServerMetadata(): array
    {
        $grantTypes = app(OAuth\AuthorizationServer::class)->grantTypes();

        $authMethods = ['client_secret_basic', 'client_secret_post', 'none'];

        $metadata = array_filter([
            'issuer' => url('/'),
            'authorization_endpoint' => route('citadel.authorizations.authorize'),
            'token_endpoint' => route('citadel.token'),
            'revocation_endpoint' => route('citadel.token.revoke'),
            'device_authorization_endpoint' => app('router')->has('citadel.device.code') ? route('citadel.device.code') : null,
            'scopes_supported' => array_keys(static::$scopes),
            'response_types_supported' => static::$implicitGrantEnabled ? ['code', 'token'] : ['code'],
            'grant_types_supported' => array_values(array_diff($grantTypes, ['implicit'])),
            'code_challenge_methods_supported' => ['S256', 'plain'],
            'token_endpoint_auth_methods_supported' => $authMethods,
            'revocation_endpoint_auth_methods_supported' => $authMethods,
        ], fn ($value) => $value !== null);

        foreach (static::$metadataExtenders as $extender) {
            $metadata = $extender($metadata);
        }

        return $metadata;
    }

    /**
     * Register the bot listeners that let users approve devices and manage tokens in Telegram.
     *
     * Call it from "listens/bot.php". Pass null as the command to skip the token command.
     *
     * @param  string[]  $abilities
     */
    public static function botListeners(?string $tokenCommand = 'token', array $abilities = ['*'], ?int $expiresInMinutes = null): void
    {
        $bot = app('listener');

        if (static::$deviceCodeGrantEnabled) {
            $bot->onReferral(Telegram\DeepLink::DEVICE_PREFIX.'{code}', [Telegram\ApproveDevice::class, 'prompt']);
            $bot->onCommand('device {code?}', [Telegram\ApproveDevice::class, 'prompt']);
            $bot->onCallbackQueryData(Telegram\ApproveDevice::CALLBACK_PREFIX.'{decision}:{code}', [Telegram\ApproveDevice::class, 'decide']);
        }

        if (! is_null($tokenCommand)) {
            Telegram\IssueAccessToken::using($tokenCommand, $abilities, $expiresInMinutes);

            $bot->onCommand($tokenCommand.' {action?}', Telegram\IssueAccessToken::class);
        }
    }

    /**
     * Instruct Citadel to enable cookie serialization.
     */
    public static function withCookieSerialization(): void
    {
        static::$unserializesCookies = true;
    }

    /**
     * Instruct Citadel to disable cookie serialization.
     */
    public static function withoutCookieSerialization(): void
    {
        static::$unserializesCookies = false;
    }

    /**
     * Instruct Citadel to enable cookie encryption.
     */
    public static function withCookieEncryption(): void
    {
        static::$decryptsCookies = true;
    }

    /**
     * Instruct Citadel to disable cookie encryption.
     */
    public static function withoutCookieEncryption(): void
    {
        static::$decryptsCookies = false;
    }

    /**
     * Get the default user provider name used for OAuth tokens.
     */
    public static function defaultProvider(): ?string
    {
        return config('citadel.provider') ?: config('auth.guards.citadel.provider');
    }

    /**
     * Get the configuration of the bot connection used to verify Telegram payloads.
     *
     * @return array<string, mixed>
     */
    public static function botConnection(): array
    {
        $connection = config('citadel.telegram.connection') ?: config('bot.default', 'bot');

        return (array) config('bot.connections.'.$connection, []);
    }
}
