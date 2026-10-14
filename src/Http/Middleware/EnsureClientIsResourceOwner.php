<?php

namespace LaraGram\Citadel\Http\Middleware;

use LaraGram\Auth\AuthenticationException;
use LaraGram\Citadel\AccessToken;
use LaraGram\Citadel\Contracts\HasAbilities;
use LaraGram\Citadel\Exceptions\MissingScopeException;

/**
 * Only lets through tokens issued to a client for itself (client credentials).
 */
class EnsureClientIsResourceOwner extends ValidateToken
{
    /**
     * Validate the token against the given scopes.
     */
    protected function validate(HasAbilities $token, string ...$abilities): void
    {
        if (! $token instanceof AccessToken
            || (! is_null($token->oauth_user_id) && $token->oauth_user_id !== $token->oauth_client_id)) {
            throw new AuthenticationException;
        }

        foreach ($abilities as $scope) {
            if ($token->cant($scope)) {
                throw new MissingScopeException($scope);
            }
        }
    }
}
