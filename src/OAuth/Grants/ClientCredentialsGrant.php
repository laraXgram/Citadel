<?php

namespace LaraGram\Citadel\OAuth\Grants;

use DateInterval;
use LaraGram\Citadel\OAuth\BearerTokenResponse;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Http\Request;

/**
 * The client credentials grant (RFC 6749 section 4.4), for machine-to-machine access.
 */
class ClientCredentialsGrant extends AbstractGrant
{
    /**
     * Get the grant type identifier.
     */
    public function getIdentifier(): string
    {
        return 'client_credentials';
    }

    /**
     * Respond to an access token request.
     */
    public function respondToAccessTokenRequest(Request $request, DateInterval $accessTokenTTL): BearerTokenResponse
    {
        $client = $this->validateClient($request);

        if (! $client->confidential()) {
            throw OAuthServerException::invalidClient('The client credentials grant requires a confidential client.');
        }

        $scopes = $this->validateScopes($this->stringParameter($request, 'scope', $this->defaultScope));

        return $this->respondWithTokens($accessTokenTTL, $client, null, $this->finalizeScopes($scopes, $client), false);
    }
}
