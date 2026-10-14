<?php

namespace LaraGram\Citadel\Events;

use LaraGram\Citadel\DeviceCode;

/**
 * Dispatched when a device asks for authorization, before any user has seen the code.
 */
class DeviceAuthorizationRequested
{
    /**
     * Create a new event instance.
     */
    public function __construct(
        public DeviceCode $deviceCode,
    ) {
    }
}
