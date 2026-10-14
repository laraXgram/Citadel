<?php

namespace LaraGram\Citadel\Telegram;

use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\DeviceCode;

/**
 * Builds the t.me links that open the bot on a Citadel action.
 */
class DeepLink
{
    /**
     * The start parameter prefix of device approvals.
     */
    public const DEVICE_PREFIX = 'device-';

    /**
     * Get the link that opens the bot to approve the given device, if bot approval is enabled.
     */
    public static function forDeviceCode(DeviceCode $deviceCode): ?string
    {
        if (! config('citadel.telegram.device_approval', true)) {
            return null;
        }

        return static::start(static::DEVICE_PREFIX.$deviceCode->user_code);
    }

    /**
     * Get the link that starts the bot with the given parameter.
     */
    public static function start(string $parameter): ?string
    {
        $username = ltrim((string) (Citadel::botConnection()['username'] ?? ''), '@');

        return $username === '' ? null : 'https://t.me/'.$username.'?start='.$parameter;
    }
}
