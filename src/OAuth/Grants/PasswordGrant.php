<?php

namespace LaraGram\Citadel\OAuth\Grants;

use DateInterval;
use LaraGram\Citadel\Client;
use LaraGram\Citadel\OAuth\BearerTokenResponse;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Contracts\Auth\Authenticatable;
use LaraGram\Http\Request;
use RuntimeException;

/**
 * The legacy resource owner password credentials grant. Disabled unless enabled explicitly.
 */
class PasswordGrant extends AbstractGrant
{
    /**
     * Get the grant type identifier.
     */
    public function getIdentifier(): string
    {
        return 'password';
    }

    /**
     * Respond to an access token request.
     */
    public function respondToAccessTokenRequest(Request $request, DateInterval $accessTokenTTL): BearerTokenResponse
    {
        $client = $this->validateClient($request);

        $scopes = $this->validateScopes($this->stringParameter($request, 'scope', $this->defaultScope));

        $username = $this->stringParameter($request, 'username');
        $password = $this->stringParameter($request, 'password');

        if (blank($username)) {
            throw OAuthServerException::invalidRequest('username');
        }

        if (blank($password)) {
            throw OAuthServerException::invalidRequest('password');
        }

        $user = $this->findUser($username, $password, $client)
            ?? throw OAuthServerException::invalidCredentials();

        return $this->respondWithTokens(
            $accessTokenTTL, $client, $user->getAuthIdentifier(), $this->finalizeScopes($scopes, $client)
        );
    }

    /**
     * Find and validate the user for the given credentials.
     *
     * The user model may define "findAndValidateForCitadel($username, $password)",
     * "findForCitadel($username)" or "validateForCitadelPasswordGrant($password)".
     */
    protected function findUser(string $username, string $password, Client $client): ?Authenticatable
    {
        $provider = $client->provider ?: \LaraGram\Citadel\Citadel::defaultProvider();

        if (is_null($model = config('auth.providers.'.$provider.'.model'))) {
            throw new RuntimeException('Unable to determine authentication model from configuration.');
        }

        if (method_exists($model, 'findAndValidateForCitadel')) {
            return (new $model)->findAndValidateForCitadel($username, $password, $client);
        }

        $user = method_exists($model, 'findForCitadel')
            ? (new $model)->findForCitadel($username, $client)
            : (new $model)->where('email', $username)->first();

        if (! $user) {
            return null;
        }

        if (method_exists($user, 'validateForCitadelPasswordGrant')) {
            return $user->validateForCitadelPasswordGrant($password) ? $user : null;
        }

        return app('hash')->check($password, $user->getAuthPassword()) ? $user : null;
    }
}
