<?php

namespace LaraGram\Citadel\OAuth;

use LaraGram\Citadel\Citadel;
use LaraGram\Http\Request;
use UnexpectedValueException;

/**
 * Validates the bearer access tokens presented to the API.
 */
class ResourceServer
{
    /**
     * Create a new resource server.
     */
    public function __construct(
        protected CryptKey $publicKey,
    ) {
        //
    }

    /**
     * Validate the access token of the request and return its attributes.
     *
     * @return array{oauth_access_token_id: string|null, oauth_client_id: string|null, oauth_user_id: string|null, oauth_scopes: string[]}
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function validateAuthenticatedRequest(Request $request): array
    {
        $jwt = $request->bearerToken();

        if (blank($jwt)) {
            throw OAuthServerException::accessDenied('Missing "Authorization" header');
        }

        return $this->validateAccessToken($jwt);
    }

    /**
     * Validate a JWT access token and return its attributes.
     *
     * @return array{oauth_access_token_id: string|null, oauth_client_id: string|null, oauth_user_id: string|null, oauth_scopes: string[]}
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function validateAccessToken(string $jwt): array
    {
        try {
            $claims = Jwt::decode($jwt, $this->publicKey);
        } catch (UnexpectedValueException $e) {
            throw OAuthServerException::accessDenied('Access token could not be verified', null, $e);
        }

        if (! isset($claims['jti'], $claims['aud'])) {
            throw OAuthServerException::accessDenied('Access token is invalid');
        }

        if ($this->isAccessTokenRevoked((string) $claims['jti'])) {
            throw OAuthServerException::accessDenied('Access token has been revoked');
        }

        return [
            'oauth_access_token_id' => (string) $claims['jti'],
            'oauth_client_id' => (string) $claims['aud'],
            'oauth_user_id' => isset($claims['sub']) ? (string) $claims['sub'] : null,
            'oauth_scopes' => array_values((array) ($claims['scopes'] ?? [])),
        ];
    }

    /**
     * Determine if the access token has been revoked.
     */
    protected function isAccessTokenRevoked(string $tokenId): bool
    {
        return Citadel::token()->newQuery()->whereKey($tokenId)->where('revoked', false)->doesntExist();
    }
}
