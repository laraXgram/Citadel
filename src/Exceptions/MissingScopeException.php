<?php

namespace LaraGram\Citadel\Exceptions;

class MissingScopeException extends MissingAbilityException
{
    /**
     * Create a new missing scope exception.
     *
     * @param  string[]|string  $scopes
     */
    public function __construct(array|string $scopes = [], string $message = 'Invalid scope(s) provided.')
    {
        parent::__construct($scopes, $message);
    }
}
