<?php

namespace LaraGram\Citadel\OAuth\Grants;

use LaraGram\Citadel\Client;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Http\Request;

trait ValidatesAuthorizationRequests
{
    /**
     * Resolve the client and redirect URI of an authorization request.
     *
     * Errors before the redirect URI is trusted are shown to the user, never redirected.
     *
     * @return array{0: \LaraGram\Citadel\Client, 1: string}
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    protected function validateClientAndRedirectUri(Request $request): array
    {
        $client = $this->getClientOrFail($request->query('client_id'));

        $redirectUri = $request->query('redirect_uri');

        if (! is_null($redirectUri)) {
            if (! is_string($redirectUri) || ! $client->allowsRedirectUri($redirectUri)) {
                throw OAuthServerException::invalidClient('The redirect URI is not registered for the client.');
            }

            return [$client, $redirectUri];
        }

        $registered = $client->redirect_uris ?? [];

        if (count($registered) !== 1) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }

        return [$client, $registered[0]];
    }
}
