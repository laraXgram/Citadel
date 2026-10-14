<?php

namespace LaraGram\Citadel\Http\Middleware;

use LaraGram\Citadel\Contracts\HasAbilities;
use LaraGram\Citadel\Exceptions\MissingAbilityException;

/**
 * Requires every given ability (or scope).
 */
class CheckAbilities extends ValidateToken
{
    /**
     * Validate the token against the given abilities.
     */
    protected function validate(HasAbilities $token, string ...$abilities): void
    {
        foreach ($abilities as $ability) {
            if ($token->cant($ability)) {
                throw $this->missing($ability);
            }
        }
    }

    /**
     * Create the exception for the missing abilities.
     *
     * @param  string[]|string  $abilities
     */
    protected function missing(array|string $abilities): MissingAbilityException
    {
        return new MissingAbilityException($abilities);
    }
}
