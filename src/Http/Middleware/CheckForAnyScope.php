<?php

namespace LaraGram\Citadel\Http\Middleware;

use LaraGram\Citadel\Exceptions\MissingAbilityException;
use LaraGram\Citadel\Exceptions\MissingScopeException;

/**
 * Requires at least one of the given scopes, reporting a MissingScopeException.
 */
class CheckForAnyScope extends CheckForAnyAbility
{
    /**
     * Create the exception for the missing scopes.
     *
     * @param  string[]  $abilities
     */
    protected function missing(array $abilities): MissingAbilityException
    {
        return new MissingScopeException($abilities);
    }
}
