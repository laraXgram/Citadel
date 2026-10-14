<?php

namespace LaraGram\Citadel\Events;

class TokenAuthenticated
{
    /**
     * Create a new event instance.
     *
     * @param  \LaraGram\Citadel\PersonalAccessToken  $token
     */
    public function __construct(
        public $token,
    ) {
    }
}
