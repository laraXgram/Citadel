<?php

namespace LaraGram\Citadel\Http\Middleware;

use LaraGram\Citadel\Exceptions\MissingAbilityException;
use LaraGram\Citadel\Exceptions\MissingScopeException;

/**
 * Requires every given scope, reporting a MissingScopeException.
 */
class CheckScopes extends CheckAbilities
{
    /**
     * Create the exception for the missing scopes.
     *
     * @param  string[]|string  $abilities
     */
    protected function missing(array|string $abilities): MissingAbilityException
    {
        return new MissingScopeException($abilities);
    }
}
