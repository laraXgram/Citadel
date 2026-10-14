<?php

namespace LaraGram\Citadel\OAuth;

use DateInterval;
use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\ClientRepository;
use LaraGram\Citadel\DeviceCode;
use LaraGram\Citadel\Events\AccessTokenRevoked;
use LaraGram\Citadel\OAuth\Grants\AbstractGrant;
use LaraGram\Citadel\OAuth\Grants\DeviceCodeGrant;
use LaraGram\Contracts\Encryption\DecryptException;
use LaraGram\Contracts\Events\Dispatcher;
use LaraGram\Encryption\Encrypter;
use LaraGram\Http\JsonResponse;
use LaraGram\Http\RedirectResponse;
use LaraGram\Http\Request;
use LaraGram\Http\Response;
use UnexpectedValueException;

/**
 * The OAuth 2 authorization server: routes token, authorization, device and
 * revocation requests to the enabled grants.
 */
class AuthorizationServer
{
    /**
     * The enabled grants, keyed by their identifier.
     *
     * @var array<string, \LaraGram\Citadel\OAuth\Grants\AbstractGrant>
     */
    protected array $grants = [];

    /**
     * The access token lifetime of each grant.
     *
     * @var array<string, \DateInterval>
     */
    protected array $accessTokenTTLs = [];

    /**
     * The default scope.
     */
    protected string $defaultScope = '';

    /**
     * Indicates if refresh tokens are rotated.
     */
    protected bool $revokeRefreshTokens = true;

    /**
     * Create a new authorization server.
     */
    public function __construct(
        protected ClientRepository $clients,
        protected CryptKey $privateKey,
        protected Encrypter $encrypter,
        protected Dispatcher $events,
    ) {
        //
    }

    /**
     * Enable a grant type on the server.
     */
    public function enableGrantType(AbstractGrant $grant, ?DateInterval $accessTokenTTL = null): void
    {
        $grant->setServices($this->clients, $this->privateKey, $this->encrypter, $this->events)
            ->setDefaultScope($this->defaultScope)
            ->revokeRefreshTokens($this->revokeRefreshTokens);

        $this->grants[$grant->getIdentifier()] = $grant;

        $this->accessTokenTTLs[$grant->getIdentifier()] = $accessTokenTTL ?? new DateInterval('PT1H');
    }

    /**
     * Set the default scope.
     */
    public function setDefaultScope(string $defaultScope): void
    {
        $this->defaultScope = $defaultScope;
    }

    /**
     * Set whether refresh tokens are rotated.
     */
    public function revokeRefreshTokens(bool $revokeRefreshTokens): void
    {
        $this->revokeRefreshTokens = $revokeRefreshTokens;
    }

    /**
     * Get an enabled grant by its identifier.
     */
    public function getGrant(string $identifier): ?AbstractGrant
    {
        return $this->grants[$identifier] ?? null;
    }

    /**
     * Get the identifiers of the enabled grants.
     *
     * @return string[]
     */
    public function grantTypes(): array
    {
        return array_keys($this->grants);
    }

    /**
     * Respond to a request of the token endpoint.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function respondToAccessTokenRequest(Request $request): JsonResponse
    {
        foreach ($this->grants as $identifier => $grant) {
            if ($grant->canRespondToAccessTokenRequest($request)) {
                return $grant->respondToAccessTokenRequest($request, $this->accessTokenTTLs[$identifier])->toResponse();
            }
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Validate a request of the authorization endpoint.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function validateAuthorizationRequest(Request $request): AuthorizationRequest
    {
        foreach ($this->grants as $grant) {
            if ($grant->canRespondToAuthorizationRequest($request)) {
                return $grant->validateAuthorizationRequest($request);
            }
        }

        throw OAuthServerException::unsupportedResponseType();
    }

    /**
     * Complete an authorization request once the user decided.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function completeAuthorizationRequest(AuthorizationRequest $authRequest): RedirectResponse
    {
        $grant = $this->getGrant($authRequest->grantTypeId)
            ?? throw OAuthServerException::unsupportedResponseType();

        return $grant->completeAuthorizationRequest($authRequest, $this->accessTokenTTLs[$authRequest->grantTypeId]);
    }

    /**
     * Respond to a request of the device authorization endpoint.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function respondToDeviceAuthorizationRequest(Request $request): JsonResponse
    {
        return $this->deviceCodeGrant()->respondToDeviceAuthorizationRequest($request);
    }

    /**
     * Record the user's decision for a pending device code.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function completeDeviceAuthorizationRequest(DeviceCode|string $deviceCode, string|int $userId, bool $approved): DeviceCode
    {
        return $this->deviceCodeGrant()->completeDeviceAuthorizationRequest($deviceCode, $userId, $approved);
    }

    /**
     * Find a pending device code by the code the user typed.
     */
    public function findPendingDeviceCode(string $userCode): ?DeviceCode
    {
        return $this->deviceCodeGrant()->findPendingByUserCode($userCode);
    }

    /**
     * Get the device code grant.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    protected function deviceCodeGrant(): DeviceCodeGrant
    {
        $grant = $this->grants['urn:ietf:params:oauth:grant-type:device_code'] ?? null;

        return $grant instanceof DeviceCodeGrant ? $grant : throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Revoke an access or refresh token (RFC 7009).
     *
     * Unknown, invalid or foreign tokens are ignored: the endpoint always answers 200.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function revokeToken(Request $request): Response
    {
        $client = ClientCredentials::authenticate($request, $this->clients);

        $token = $request->input('token');

        if (! is_string($token) || $token === '') {
            throw OAuthServerException::invalidRequest('token');
        }

        $clientId = (string) $client->getKey();

        if (Jwt::looksLikeJwt($token)) {
            $this->revokeAccessToken($token, $clientId);
        } else {
            $this->revokeRefreshToken($token, $clientId);
        }

        return new Response('', 200, ['Cache-Control' => 'no-store']);
    }

    /**
     * Revoke an access token (and its refresh token) issued to the client.
     */
    protected function revokeAccessToken(string $jwt, string $clientId): void
    {
        try {
            $claims = Jwt::decode($jwt, $this->privateKey, ['RS256'], false);
        } catch (UnexpectedValueException) {
            return;
        }

        if (($claims['aud'] ?? null) !== $clientId || ! isset($claims['jti'])) {
            return;
        }

        $this->revokeAccessTokenById($claims['jti']);
    }

    /**
     * Revoke a refresh token (and its access token) issued to the client.
     */
    protected function revokeRefreshToken(string $encrypted, string $clientId): void
    {
        try {
            $payload = json_decode($this->encrypter->decryptString($encrypted), true);
        } catch (DecryptException) {
            return;
        }

        if (! is_array($payload) || (string) ($payload['client_id'] ?? '') !== $clientId || ! isset($payload['refresh_token_id'])) {
            return;
        }

        $refreshToken = Citadel::refreshToken()->newQuery()->whereKey($payload['refresh_token_id'])->first();

        if ($refreshToken) {
            $refreshToken->revoke();

            $this->revokeAccessTokenById($refreshToken->access_token_id);
        }
    }

    /**
     * Revoke the access token with the given ID together with its refresh tokens.
     */
    protected function revokeAccessTokenById(string $tokenId): void
    {
        if (Citadel::token()->newQuery()->whereKey($tokenId)->where('revoked', false)->update(['revoked' => true])) {
            $this->events->dispatch(new AccessTokenRevoked($tokenId));
        }

        Citadel::refreshToken()->newQuery()->where('access_token_id', $tokenId)->update(['revoked' => true]);
    }
}
