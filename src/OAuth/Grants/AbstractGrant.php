<?php

namespace LaraGram\Citadel\OAuth\Grants;

use DateInterval;
use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\Client;
use LaraGram\Citadel\ClientRepository;
use LaraGram\Citadel\Events\AccessTokenCreated;
use LaraGram\Citadel\Events\RefreshTokenCreated;
use LaraGram\Citadel\OAuth\AuthorizationRequest;
use LaraGram\Citadel\OAuth\BearerTokenResponse;
use LaraGram\Citadel\OAuth\ClientCredentials;
use LaraGram\Citadel\OAuth\CryptKey;
use LaraGram\Citadel\OAuth\Jwt;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Citadel\RefreshToken;
use LaraGram\Citadel\Token;
use LaraGram\Contracts\Auth\UserProvider;
use LaraGram\Contracts\Encryption\DecryptException;
use LaraGram\Contracts\Events\Dispatcher;
use LaraGram\Encryption\Encrypter;
use LaraGram\Http\JsonResponse;
use LaraGram\Http\RedirectResponse;
use LaraGram\Http\Request;
use LaraGram\Support\Facades\Date;
use LogicException;

abstract class AbstractGrant
{
    /**
     * The maximum number of attempts to generate a unique identifier.
     */
    protected const MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS = 10;

    /**
     * The client repository.
     */
    protected ClientRepository $clients;

    /**
     * The key used to sign access tokens.
     */
    protected CryptKey $privateKey;

    /**
     * The encrypter used for authorization codes, refresh tokens and device codes.
     */
    protected Encrypter $encrypter;

    /**
     * The event dispatcher.
     */
    protected Dispatcher $events;

    /**
     * The default scope, used when a request names none.
     */
    protected string $defaultScope = '';

    /**
     * The lifetime of the refresh tokens issued by this grant.
     */
    protected ?DateInterval $refreshTokenTTL = null;

    /**
     * Indicates if refresh tokens are rotated (and the used one revoked).
     */
    protected bool $revokeRefreshTokens = true;

    /**
     * Get the grant type identifier.
     */
    abstract public function getIdentifier(): string;

    /**
     * Respond to an access token request.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    abstract public function respondToAccessTokenRequest(Request $request, DateInterval $accessTokenTTL): BearerTokenResponse;

    /**
     * Determine if the grant can respond to the given access token request.
     */
    public function canRespondToAccessTokenRequest(Request $request): bool
    {
        return $request->input('grant_type') === $this->getIdentifier();
    }

    /**
     * Determine if the grant can respond to the given authorization request.
     */
    public function canRespondToAuthorizationRequest(Request $request): bool
    {
        return false;
    }

    /**
     * Validate an authorization request.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function validateAuthorizationRequest(Request $request): AuthorizationRequest
    {
        throw new LogicException('This grant cannot validate an authorization request.');
    }

    /**
     * Complete an authorization request once the user decided.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function completeAuthorizationRequest(AuthorizationRequest $authRequest, DateInterval $accessTokenTTL): RedirectResponse
    {
        throw new LogicException('This grant cannot complete an authorization request.');
    }

    /**
     * Determine if the grant can respond to a device authorization request.
     */
    public function canRespondToDeviceAuthorizationRequest(Request $request): bool
    {
        return false;
    }

    /**
     * Respond to a device authorization request.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function respondToDeviceAuthorizationRequest(Request $request): JsonResponse
    {
        throw new LogicException('This grant cannot respond to a device authorization request.');
    }

    /**
     * Set the services shared by every grant.
     */
    public function setServices(ClientRepository $clients, CryptKey $privateKey, Encrypter $encrypter, Dispatcher $events): static
    {
        $this->clients = $clients;
        $this->privateKey = $privateKey;
        $this->encrypter = $encrypter;
        $this->events = $events;

        return $this;
    }

    /**
     * Set the default scope.
     */
    public function setDefaultScope(string $scope): static
    {
        $this->defaultScope = $scope;

        return $this;
    }

    /**
     * Set the lifetime of the refresh tokens.
     */
    public function setRefreshTokenTTL(?DateInterval $refreshTokenTTL): static
    {
        $this->refreshTokenTTL = $refreshTokenTTL;

        return $this;
    }

    /**
     * Set whether refresh tokens are rotated.
     */
    public function revokeRefreshTokens(bool $revokeRefreshTokens): static
    {
        $this->revokeRefreshTokens = $revokeRefreshTokens;

        return $this;
    }

    /**
     * Authenticate the client of the request.
     *
     * Confidential clients must present their secret (HTTP Basic or the body);
     * public clients are identified by their ID alone.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    protected function validateClient(Request $request): Client
    {
        [$clientId, $clientSecret] = ClientCredentials::fromRequest($request);

        $client = $this->getClientOrFail($clientId);

        if ($client->confidential() && ! $this->clients->validateSecret($client, $clientSecret)) {
            throw OAuthServerException::invalidClient();
        }

        return $client;
    }

    /**
     * Get an active client that supports this grant, or fail.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    protected function getClientOrFail(?string $clientId): Client
    {
        if (blank($clientId)) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        $client = $this->clients->findActive($clientId);

        if (! $client) {
            throw OAuthServerException::invalidClient();
        }

        if (! $client->hasGrantType($this->getIdentifier())) {
            throw OAuthServerException::unauthorizedClient();
        }

        return $client;
    }

    /**
     * Get a string parameter from the request body (or query when allowed).
     */
    protected function stringParameter(Request $request, string $key, ?string $default = null): ?string
    {
        $value = $request->input($key, $default);

        return is_scalar($value) ? (string) $value : $default;
    }

    /**
     * Validate the requested scopes, falling back to the default scope.
     *
     * @return string[]
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    protected function validateScopes(string|array|null $scopes, ?string $redirectUri = null): array
    {
        if (is_string($scopes)) {
            $scopes = array_values(array_filter(explode(' ', trim($scopes)), fn (string $scope) => $scope !== ''));
        }

        $scopes = $scopes ?: Citadel::defaultScopes();

        foreach ($scopes as $scope) {
            if (! is_string($scope) || ! Citadel::hasScope($scope)) {
                throw OAuthServerException::invalidScope((string) $scope, $redirectUri);
            }
        }

        return array_values(array_unique($scopes));
    }

    /**
     * Filter the scopes down to the ones the client and grant may receive.
     *
     * @param  string[]  $scopes
     * @return string[]
     */
    protected function finalizeScopes(array $scopes, Client $client): array
    {
        return collect($scopes)
            ->unless(in_array($this->getIdentifier(), ['password', 'client_credentials'], true),
                fn ($scopes) => $scopes->reject(fn (string $scope): bool => $scope === '*')
            )
            ->filter(fn (string $scope): bool => Citadel::hasScope($scope) && $client->hasScope($scope))
            ->values()
            ->all();
    }

    /**
     * Issue and persist a new access token.
     *
     * @param  string[]  $scopes
     */
    protected function issueAccessToken(DateInterval $accessTokenTTL, Client $client, string|int|null $userId, array $scopes): Token
    {
        $token = Citadel::token()->forceFill([
            'id' => $this->generateUniqueIdentifier(),
            'user_id' => $userId,
            'client_id' => $client->getKey(),
            'scopes' => $scopes,
            'revoked' => false,
            'expires_at' => Date::now()->add($accessTokenTTL),
        ]);

        $token->save();

        $this->events->dispatch(new AccessTokenCreated(
            $token->getKey(), is_null($userId) ? null : (string) $userId, (string) $client->getKey()
        ));

        return $token;
    }

    /**
     * Issue and persist a new refresh token, returning its encrypted form.
     */
    protected function issueRefreshToken(Token $accessToken): ?string
    {
        if (is_null($this->refreshTokenTTL)) {
            return null;
        }

        $expiresAt = Date::now()->add($this->refreshTokenTTL);

        $refreshToken = Citadel::refreshToken()->forceFill([
            'id' => $this->generateUniqueIdentifier(),
            'access_token_id' => $accessToken->getKey(),
            'revoked' => false,
            'expires_at' => $expiresAt,
        ]);

        $refreshToken->save();

        $this->events->dispatch(new RefreshTokenCreated($refreshToken->getKey(), $accessToken->getKey()));

        return $this->encrypt([
            'client_id' => (string) $accessToken->client_id,
            'refresh_token_id' => $refreshToken->getKey(),
            'access_token_id' => $accessToken->getKey(),
            'scopes' => $accessToken->scopes ?? [],
            'user_id' => $accessToken->user_id,
            'expire_time' => $expiresAt->getTimestamp(),
        ]);
    }

    /**
     * Convert an access token into its signed JWT form.
     */
    protected function convertToJwt(Token $token): string
    {
        $now = time();

        return Jwt::encode([
            'aud' => (string) $token->client_id,
            'jti' => $token->getKey(),
            'iat' => $now,
            'nbf' => $now,
            'exp' => $token->expires_at->getTimestamp(),
            'sub' => (string) ($token->user_id ?? $token->client_id),
            'scopes' => array_values($token->scopes ?? []),
        ], $this->privateKey);
    }

    /**
     * Build the bearer token response for the given tokens.
     */
    protected function makeBearerTokenResponse(Token $accessToken, ?string $refreshToken, DateInterval $accessTokenTTL): BearerTokenResponse
    {
        $expiresIn = Date::now()->add($accessTokenTTL)->getTimestamp() - time();

        return new Citadel::$bearerTokenResponse($accessToken, $this->convertToJwt($accessToken), $expiresIn, $refreshToken);
    }

    /**
     * Issue an access token (with a refresh token when enabled) and build the response.
     *
     * @param  string[]  $scopes
     */
    protected function respondWithTokens(DateInterval $accessTokenTTL, Client $client, string|int|null $userId, array $scopes, bool $withRefreshToken = true): BearerTokenResponse
    {
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $userId, $scopes);

        $refreshToken = $withRefreshToken && $client->hasGrantType('refresh_token')
            ? $this->issueRefreshToken($accessToken)
            : null;

        return $this->makeBearerTokenResponse($accessToken, $refreshToken, $accessTokenTTL);
    }

    /**
     * Resolve the user provider for the given client.
     */
    protected function userProvider(Client $client): UserProvider
    {
        $provider = $client->provider ?: Citadel::defaultProvider();

        return app('auth')->createUserProvider($provider)
            ?? throw new LogicException("Unable to create the [{$provider}] user provider.");
    }

    /**
     * Encrypt a payload for the client.
     *
     * @param  array<string, mixed>  $payload
     */
    protected function encrypt(array $payload): string
    {
        return $this->encrypter->encryptString(json_encode($payload, JSON_THROW_ON_ERROR));
    }

    /**
     * Decrypt a payload issued by this server.
     *
     * @return array<string, mixed>|null
     */
    protected function decrypt(string $payload): ?array
    {
        try {
            $decoded = json_decode($this->encrypter->decryptString($payload), true);
        } catch (DecryptException) {
            return null;
        }

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Generate a new unique identifier.
     */
    protected function generateUniqueIdentifier(int $length = 40): string
    {
        return bin2hex(random_bytes($length));
    }
}
