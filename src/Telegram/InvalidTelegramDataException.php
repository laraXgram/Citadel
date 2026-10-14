<?php

namespace LaraGram\Citadel\Telegram;

use RuntimeException;

class InvalidTelegramDataException extends RuntimeException
{
    /**
     * The payload is not a valid Telegram payload.
     */
    public static function malformed(): static
    {
        return new static('The Telegram payload is malformed.');
    }

    /**
     * The payload signature does not match.
     */
    public static function invalidSignature(): static
    {
        return new static('The Telegram payload signature is invalid.');
    }

    /**
     * The payload is older than the allowed lifetime.
     */
    public static function expired(): static
    {
        return new static('The Telegram payload has expired.');
    }

    /**
     * No bot token is configured to verify payloads.
     */
    public static function missingBotToken(): static
    {
        return new static('No bot token is configured to verify Telegram payloads (see the citadel.telegram.connection option).');
    }
}
