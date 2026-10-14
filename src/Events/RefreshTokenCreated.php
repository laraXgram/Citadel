<?php

namespace LaraGram\Citadel\Events;

class RefreshTokenCreated
{
    /**
     * Create a new event instance.
     */
    public function __construct(
        public string $refreshTokenId,
        public string $accessTokenId,
    ) {
    }
}
