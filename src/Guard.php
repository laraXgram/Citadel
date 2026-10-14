<?php

namespace LaraGram\Citadel;

use Exception;
use LaraGram\Auth\GuardHelpers;
use LaraGram\Citadel\Events\TokenAuthenticated;
use LaraGram\Citadel\OAuth\Jwt;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Citadel\OAuth\ResourceServer;
use LaraGram\Contracts\Auth\Authenticatable;
use LaraGram\Contracts\Auth\Factory as AuthFactory;
use LaraGram\Contracts\Auth\Guard as GuardContract;
use LaraGram\Contracts\Auth\UserProvider;
use LaraGram\Contracts\Encryption\DecryptException;
use LaraGram\Contracts\Encryption\Encrypter;
use LaraGram\Cookie\CookieValuePrefix;
use LaraGram\Cookie\Middleware\EncryptCookies;
use LaraGram\Http\Request;
use LaraGram\Support\Arr;
use LaraGram\Support\Traits\Macroable;

/**
 * The "citadel" guard.
 *
 * A request is authenticated by the first source that knows its user:
 *
 *  1. the stateful guards listed in "citadel.guard" (session, Luna's "telegram" guard, ...),
 *  2. a personal access token ("id|secret") in the Authorization header,
 *  3. an OAuth access token (JWT) in the Authorization header,
 *  4. the API token cookie created by the CreateFreshApiToken middleware.
 */
class Guard implements GuardContract
{
    use GuardHelpers, Macroable;

    /**
     * The client that issued the current OAuth access token.
     */
    protected ?Client $client = null;

    /**
     * Create a new guard instance.
     */
    public function __construct(
        protected string $name,
        protected AuthFactory $auth,
        protected ResourceServer $server,
        protected ClientRepository $clients,
        protected Encrypter $encrypter,
        protected Request $request,
        ?UserProvider $provider = null,
        protected ?string $providerName = null,
        protected ?int $expiration = null,
        protected bool $trackLastUsedAt = true,
    ) {
        $this->provider = $provider;
    }

    /**
     * Get the user for the incoming request.
     */
    public function user(): ?Authenticatable
    {
        if (! is_null($this->user)) {
            return $this->user;
        }

        if ($user = $this->authenticateViaStatefulGuards()) {
            return $this->user = $user;
        }

        if ($token = $this->getTokenFromRequest()) {
            return $this->user = Jwt::looksLikeJwt($token)
                ? $this->authenticateViaOAuthToken($token)
                : $this->authenticateViaPersonalAccessToken($token);
        }

        if ($this->request->cookie(Citadel::cookie())) {
            return $this->user = $this->authenticateViaCookie();
        }

        return null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array{request?: \LaraGram\Http\Request}  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        if (! isset($credentials['request'])) {
            return false;
        }

        return ! is_null((new static(
            $this->name,
            $this->auth,
            $this->server,
            $this->clients,
            $this->encrypter,
            $credentials['request'],
            $this->provider,
            $this->providerName,
            $this->expiration,
            $this->trackLastUsedAt,
        ))->user());
    }

    /**
     * Get the client of the current OAuth access token, if any.
     */
    public function client(): ?Client
    {
        if (! is_null($this->client)) {
            return $this->client;
        }

        $token = $this->getTokenFromRequest();

        if ($token && Jwt::looksLikeJwt($token)) {
            try {
                $attributes = $this->server->validateAccessToken($token);
            } catch (OAuthServerException) {
                return null;
            }

            return $this->client = $this->clients->findActive($attributes['oauth_client_id']);
        }

        if ($this->request->cookie(Citadel::cookie()) && $payload = $this->getTokenViaCookie()) {
            return $this->client = isset($payload['aud']) ? $this->clients->findActive($payload['aud']) : null;
        }

        return null;
    }

    /**
     * Authenticate the request through the configured stateful guards.
     */
    protected function authenticateViaStatefulGuards(): ?Authenticatable
    {
        foreach (Arr::wrap(config('citadel.guard', 'web')) as $guard) {
            if ($guard === $this->name) {
                continue;
            }

            if ($user = $this->auth->guard($guard)->user()) {
                return $this->supportsTokens($user)
                    ? $user->withAccessToken(new TransientToken)
                    : $user;
            }
        }

        return null;
    }

    /**
     * Authenticate the request through a personal access token.
     */
    protected function authenticateViaPersonalAccessToken(string $token): ?Authenticatable
    {
        if (! $this->isValidPersonalAccessToken($token)) {
            return null;
        }

        $model = Citadel::personalAccessTokenModel();

        $accessToken = $model::findToken($token);

        if (! $this->isValidAccessToken($accessToken) || ! $this->supportsTokens($accessToken->tokenable)) {
            return null;
        }

        $tokenable = $accessToken->tokenable->withAccessToken($accessToken);

        event(new TokenAuthenticated($accessToken));

        if ($this->trackLastUsedAt) {
            $this->updateLastUsedAt($accessToken);
        }

        return $tokenable;
    }

    /**
     * Authenticate the request through an OAuth access token.
     */
    protected function authenticateViaOAuthToken(string $jwt): ?Authenticatable
    {
        try {
            $attributes = $this->server->validateAccessToken($jwt);
        } catch (OAuthServerException) {
            return null;
        }

        $client = $this->clients->findActive($attributes['oauth_client_id']);

        if (! $client || ($client->provider && $this->providerName && $client->provider !== $this->providerName)) {
            return null;
        }

        $this->setClient($client);

        $userId = $attributes['oauth_user_id'];

        if (empty($userId) || ($userId === $attributes['oauth_client_id'] && $client->hasGrantType('client_credentials'))) {
            return null;
        }

        try {
            $user = $this->providerFor($client)?->retrieveById($userId);
        } catch (Exception) {
            return null;
        }

        return $this->supportsTokens($user)
            ? $user->withAccessToken(new AccessToken($attributes))
            : null;
    }

    /**
     * Authenticate the request through the API token cookie.
     */
    protected function authenticateViaCookie(): ?Authenticatable
    {
        if (! $payload = $this->getTokenViaCookie()) {
            return null;
        }

        try {
            $user = $this->providerFor()?->retrieveById($payload['sub']);
        } catch (Exception) {
            return null;
        }

        return $this->supportsTokens($user)
            ? $user->withAccessToken(new TransientToken)
            : $user;
    }

    /**
     * Get the decrypted and verified payload of the API token cookie.
     *
     * @return array<string, mixed>|null
     */
    protected function getTokenViaCookie(): ?array
    {
        try {
            $payload = $this->decodeJwtTokenCookie();
        } catch (Exception) {
            return null;
        }

        if (! isset($payload['sub'])) {
            return null;
        }

        if (! Citadel::$ignoreCsrfToken && ! $this->validCsrf($payload)) {
            return null;
        }

        return $payload;
    }

    /**
     * Decode and decrypt the JWT token cookie.
     *
     * @return array<string, mixed>
     */
    protected function decodeJwtTokenCookie(): array
    {
        $jwt = $this->request->cookie(Citadel::cookie());

        return Jwt::decode(
            Citadel::$decryptsCookies
                ? CookieValuePrefix::remove($this->encrypter->decrypt($jwt, Citadel::$unserializesCookies))
                : $jwt,
            Citadel::tokenEncryptionKey($this->encrypter),
            ['HS256'],
        );
    }

    /**
     * Determine if the CSRF / header are valid and match.
     *
     * @param  array<string, mixed>  $payload
     */
    protected function validCsrf(array $payload): bool
    {
        $requestToken = $this->getCsrfTokenFromRequest();

        return isset($payload['csrf'])
            && is_string($requestToken)
            && hash_equals($payload['csrf'], $requestToken);
    }

    /**
     * Get the CSRF token from the request.
     */
    protected function getCsrfTokenFromRequest(): ?string
    {
        $token = $this->request->header('X-CSRF-TOKEN');

        if (! $token && $header = $this->request->header('X-XSRF-TOKEN')) {
            try {
                $token = CookieValuePrefix::remove($this->encrypter->decrypt($header, static::serialized()));
            } catch (DecryptException) {
                $token = null;
            }
        }

        return $token;
    }

    /**
     * Get the bearer token from the request.
     */
    protected function getTokenFromRequest(): ?string
    {
        if (is_callable(Citadel::$accessTokenRetrievalCallback)) {
            return (string) (Citadel::$accessTokenRetrievalCallback)($this->request) ?: null;
        }

        $token = $this->request->bearerToken();

        return empty($token) ? null : $token;
    }

    /**
     * Determine if the personal access token has a valid format.
     */
    protected function isValidPersonalAccessToken(string $token): bool
    {
        if (str_contains($token, '|')) {
            $model = new (Citadel::personalAccessTokenModel());

            if ($model->getKeyType() === 'int') {
                [$id, $token] = explode('|', $token, 2);

                return ctype_digit($id) && ! empty($token);
            }
        }

        return true;
    }

    /**
     * Determine if the personal access token is valid.
     */
    protected function isValidAccessToken(?PersonalAccessToken $accessToken): bool
    {
        if (! $accessToken) {
            return false;
        }

        $isValid =
            (! $this->expiration || $accessToken->created_at->gt(now()->subMinutes($this->expiration)))
            && (! $accessToken->expires_at || ! $accessToken->expires_at->isPast())
            && $this->hasValidProvider($accessToken->tokenable);

        if (is_callable(Citadel::$accessTokenAuthenticationCallback)) {
            $isValid = (bool) (Citadel::$accessTokenAuthenticationCallback)($accessToken, $isValid);
        }

        return $isValid;
    }

    /**
     * Determine if the tokenable model matches the provider of the guard.
     */
    protected function hasValidProvider(?object $tokenable): bool
    {
        if (is_null($this->providerName)) {
            return true;
        }

        $model = config("auth.providers.{$this->providerName}.model");

        return $tokenable instanceof $model;
    }

    /**
     * Store the time the personal access token was last used.
     */
    protected function updateLastUsedAt(PersonalAccessToken $accessToken): void
    {
        $connection = $accessToken->getConnection();

        if (method_exists($connection, 'hasModifiedRecords') && method_exists($connection, 'setRecordModificationState')) {
            $hasModifiedRecords = $connection->hasModifiedRecords();

            $accessToken->forceFill(['last_used_at' => now()])->save();

            $connection->setRecordModificationState($hasModifiedRecords);
        } else {
            $accessToken->forceFill(['last_used_at' => now()])->save();
        }
    }

    /**
     * Get the user provider used for OAuth users (the client's, the guard's or the default one).
     */
    protected function providerFor(?Client $client = null): ?UserProvider
    {
        $name = $client?->provider ?: $this->providerName;

        if ($name && $name === $this->providerName && $this->provider) {
            return $this->provider;
        }

        return $this->auth->createUserProvider($name ?: Citadel::defaultProvider());
    }

    /**
     * Determine if the user model supports API tokens.
     */
    protected function supportsTokens(?object $tokenable = null): bool
    {
        return $tokenable && in_array(HasApiTokens::class, class_uses_recursive(
            get_class($tokenable)
        ));
    }

    /**
     * Set the current request instance.
     */
    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Set the client for the current request.
     */
    public function setClient(Client $client): static
    {
        $this->client = $client;

        return $this;
    }

    /**
     * Get the name of the guard.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Determine if the XSRF-TOKEN cookie is serialized.
     */
    public static function serialized(): bool
    {
        return EncryptCookies::serialized('XSRF-TOKEN');
    }
}
