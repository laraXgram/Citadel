<?php

namespace LaraGram\Citadel\Telegram;

/**
 * Verifies the payloads Telegram signs for a bot: Mini App init data and
 * Login Widget (or "login_url" button) authorization data.
 *
 * @see https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
 * @see https://core.telegram.org/widgets/login#checking-authorization
 */
class TelegramAuthenticator
{
    /**
     * Create a new authenticator.
     *
     * @param  "hmac"|"signature"|"both"  $scheme
     */
    public function __construct(
        protected ?string $botToken,
        protected int $ttl = 86400,
        protected string $scheme = 'hmac',
        protected ?string $publicKey = null,
    ) {
        //
    }

    /**
     * Verify Mini App init data (the raw "Telegram.WebApp.initData" string).
     *
     * @throws \LaraGram\Citadel\Telegram\InvalidTelegramDataException
     */
    public function verifyInitData(string $initData): TelegramIdentity
    {
        parse_str($initData, $fields);

        if (! is_string($fields['hash'] ?? null) || ! is_string($fields['user'] ?? null)) {
            throw InvalidTelegramDataException::malformed();
        }

        $dataCheckString = $this->dataCheckString($fields, ['hash', 'signature']);

        if (in_array($this->scheme, ['hmac', 'both'], true)) {
            $secret = hash_hmac('sha256', $this->botToken(), 'WebAppData', true);

            if (! hash_equals(hash_hmac('sha256', $dataCheckString, $secret), $fields['hash'])) {
                throw InvalidTelegramDataException::invalidSignature();
            }
        }

        if (in_array($this->scheme, ['signature', 'both'], true)) {
            $this->verifyEd25519Signature($fields, $dataCheckString);
        }

        $this->ensureFresh($fields);

        $user = json_decode($fields['user'], true);

        if (! is_array($user) || ! isset($user['id'])) {
            throw InvalidTelegramDataException::malformed();
        }

        return TelegramIdentity::fromInitData($user, $fields);
    }

    /**
     * Verify Login Widget authorization data (id, first_name, auth_date, hash...).
     *
     * @param  array<string, mixed>  $fields
     *
     * @throws \LaraGram\Citadel\Telegram\InvalidTelegramDataException
     */
    public function verifyLoginWidget(array $fields): TelegramIdentity
    {
        $fields = array_filter($fields, fn ($value) => is_scalar($value));

        if (! isset($fields['id'], $fields['auth_date'], $fields['hash']) || ! ctype_digit((string) $fields['id'])) {
            throw InvalidTelegramDataException::malformed();
        }

        $allowed = ['id', 'first_name', 'last_name', 'username', 'photo_url', 'auth_date', 'hash'];

        $fields = array_intersect_key($fields, array_flip($allowed));

        $secret = hash('sha256', $this->botToken(), true);

        $expected = hash_hmac('sha256', $this->dataCheckString($fields, ['hash']), $secret);

        if (! hash_equals($expected, (string) $fields['hash'])) {
            throw InvalidTelegramDataException::invalidSignature();
        }

        $this->ensureFresh($fields);

        return TelegramIdentity::fromLoginWidget($fields);
    }

    /**
     * Verify the third-party Ed25519 signature of init data.
     *
     * @param  array<string, mixed>  $fields
     */
    protected function verifyEd25519Signature(array $fields, string $dataCheckString): void
    {
        $signature = is_string($fields['signature'] ?? null)
            ? base64_decode(strtr($fields['signature'], '-_', '+/'), true)
            : false;

        $publicKey = $this->publicKey ? @hex2bin($this->publicKey) : false;

        if ($signature === false || $publicKey === false || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw InvalidTelegramDataException::invalidSignature();
        }

        $botId = explode(':', $this->botToken(), 2)[0];

        if (! sodium_crypto_sign_verify_detached($signature, $botId.":WebAppData\n".$dataCheckString, $publicKey)) {
            throw InvalidTelegramDataException::invalidSignature();
        }
    }

    /**
     * Ensure the payload is not older than the allowed lifetime.
     *
     * @param  array<string, mixed>  $fields
     */
    protected function ensureFresh(array $fields): void
    {
        $authDate = (int) ($fields['auth_date'] ?? 0);

        if ($authDate <= 0 || ($this->ttl > 0 && time() - $authDate > $this->ttl)) {
            throw InvalidTelegramDataException::expired();
        }
    }

    /**
     * Build the sorted "key=value" data check string.
     *
     * @param  array<string, mixed>  $fields
     * @param  string[]  $except
     */
    protected function dataCheckString(array $fields, array $except): string
    {
        $fields = array_diff_key($fields, array_flip($except));

        ksort($fields);

        return implode("\n", array_map(
            fn ($key, $value) => $key.'='.$value, array_keys($fields), $fields
        ));
    }

    /**
     * Get the bot token.
     */
    protected function botToken(): string
    {
        return $this->botToken ?: throw InvalidTelegramDataException::missingBotToken();
    }
}
