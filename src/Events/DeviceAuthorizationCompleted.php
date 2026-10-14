<?php

namespace LaraGram\Citadel\Events;

use LaraGram\Citadel\DeviceCode;

/**
 * Dispatched when a user approves or denies a device, on the web or in the bot.
 */
class DeviceAuthorizationCompleted
{
    /**
     * Create a new event instance.
     */
    public function __construct(
        public DeviceCode $deviceCode,
        public string $userId,
        public bool $approved,
    ) {
    }
}
