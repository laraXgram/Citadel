<?php

namespace LaraGram\Citadel\Http\Middleware;

use LaraGram\Citadel\Contracts\HasAbilities;
use LaraGram\Citadel\Exceptions\MissingAbilityException;

/**
 * Requires at least one of the given abilities (or scopes).
 */
class CheckForAnyAbility extends ValidateToken
{
    /**
     * Validate the token against the given abilities.
     */
    protected function validate(HasAbilities $token, string ...$abilities): void
    {
        foreach ($abilities as $ability) {
            if ($token->can($ability)) {
                return;
            }
        }

        throw $this->missing($abilities);
    }

    /**
     * Create the exception for the missing abilities.
     *
     * @param  string[]  $abilities
     */
    protected function missing(array $abilities): MissingAbilityException
    {
        return new MissingAbilityException($abilities);
    }
}
