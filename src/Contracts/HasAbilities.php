<?php

namespace LaraGram\Citadel\Contracts;

interface HasAbilities
{
    /**
     * Determine if the token has a given ability (or scope).
     */
    public function can(string $ability): bool;

    /**
     * Determine if the token is missing a given ability (or scope).
     */
    public function cant(string $ability): bool;
}
