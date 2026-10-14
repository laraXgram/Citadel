<?php

namespace LaraGram\Citadel\OAuth\Grants;

use DateInterval;
use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\Events\AccessTokenRevoked;
use LaraGram\Citadel\OAuth\BearerTokenResponse;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Http\Request;

/**
 * The refresh token grant (RFC 6749 section 6), rotating refresh tokens by default.
 */
class RefreshTokenGrant extends AbstractGrant
{
    /**
     * Get the grant type identifier.
     */
    public function getIdentifier(): string
    {
        return 'refresh_token';
    }

    /**
     * Respond to an access token request.
     */
    public function respondToAccessTokenRequest(Request $request, DateInterval $accessTokenTTL): BearerTokenResponse
    {
        $client = $this->validateClient($request);

        $encrypted = $this->stringParameter($request, 'refresh_token');

        if (blank($encrypted)) {
            throw OAuthServerException::invalidRequest('refresh_token');
        }

        $payload = $this->decrypt($encrypted);

        if (! isset($payload['refresh_token_id'], $payload['access_token_id'], $payload['client_id'])) {
            throw OAuthServerException::invalidRefreshToken('Cannot decrypt the refresh token');
        }

        if ((string) $payload['client_id'] !== (string) $client->getKey()) {
            throw OAuthServerException::invalidRefreshToken('Token is not linked to client');
        }

        if (time() > (int) ($payload['expire_time'] ?? 0)) {
            throw OAuthServerException::invalidRefreshToken('Token has expired');
        }

        $refreshToken = Citadel::refreshToken()->newQuery()->whereKey($payload['refresh_token_id'])->first();

        if (! $refreshToken || $refreshToken->revoked) {
            throw OAuthServerException::invalidRefreshToken('Token has been revoked');
        }

        $originalScopes = (array) ($payload['scopes'] ?? []);

        $scopes = $this->validateScopes($this->stringParameter($request, 'scope') ?: $originalScopes);

        foreach ($scopes as $scope) {
            if (! in_array($scope, $originalScopes, true)) {
                throw OAuthServerException::invalidScope($scope);
            }
        }

        $previousAccessTokenId = $refreshToken->access_token_id ?: $payload['access_token_id'];

        if (Citadel::token()->newQuery()->whereKey($previousAccessTokenId)->update(['revoked' => true])) {
            $this->events->dispatch(new AccessTokenRevoked($previousAccessTokenId));
        }

        $accessToken = $this->issueAccessToken(
            $accessTokenTTL, $client, $payload['user_id'] ?? null, $this->finalizeScopes($scopes, $client)
        );

        if (! $this->revokeRefreshTokens) {
            $refreshToken->forceFill(['access_token_id' => $accessToken->getKey()])->save();

            return $this->makeBearerTokenResponse($accessToken, $encrypted, $accessTokenTTL);
        }

        $refreshToken->revoke();

        return $this->makeBearerTokenResponse($accessToken, $this->issueRefreshToken($accessToken), $accessTokenTTL);
    }
}
