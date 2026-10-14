<?php

namespace LaraGram\Citadel\Events;

class AccessTokenRevoked
{
    /**
     * Create a new event instance.
     */
    public function __construct(
        public string $tokenId,
    ) {
    }
}
