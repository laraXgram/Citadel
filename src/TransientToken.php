<?php

namespace LaraGram\Citadel;

use LaraGram\Citadel\Contracts\HasAbilities;

/**
 * The token attached to users authenticated by a stateful guard or the API
 * token cookie: they are physically logged in, so every ability is granted.
 */
class TransientToken implements HasAbilities
{
    /**
     * Determine if the token has a given ability.
     */
    public function can(string $ability): bool
    {
        return true;
    }

    /**
     * Determine if the token is missing a given ability.
     */
    public function cant(string $ability): bool
    {
        return false;
    }

    /**
     * Determine if the token is a transient token.
     */
    public function transient(): bool
    {
        return true;
    }
}
