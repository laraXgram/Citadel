<?php

namespace LaraGram\Citadel\Telegram;

use LaraGram\Contracts\Support\Arrayable;

/**
 * A Telegram user whose identity was proven by a signed Telegram payload.
 */
class TelegramIdentity implements Arrayable
{
    /**
     * Create a new Telegram identity.
     *
     * @param  "init_data"|"login_widget"  $source
     * @param  array<string, mixed>  $fields
     */
    public function __construct(
        public readonly int $id,
        public readonly string $firstName,
        public readonly ?string $lastName,
        public readonly ?string $username,
        public readonly ?string $languageCode,
        public readonly ?string $photoUrl,
        public readonly bool $isPremium,
        public readonly int $authDate,
        public readonly string $source,
        public readonly array $fields = [],
    ) {
        //
    }

    /**
     * Create an identity from the "user" object of Mini App init data.
     *
     * @param  array<string, mixed>  $user
     * @param  array<string, mixed>  $fields
     */
    public static function fromInitData(array $user, array $fields): static
    {
        return new static(
            (int) $user['id'],
            (string) ($user['first_name'] ?? ''),
            $user['last_name'] ?? null,
            $user['username'] ?? null,
            $user['language_code'] ?? null,
            $user['photo_url'] ?? null,
            (bool) ($user['is_premium'] ?? false),
            (int) ($fields['auth_date'] ?? 0),
            'init_data',
            $fields,
        );
    }

    /**
     * Create an identity from the fields of a Login Widget payload.
     *
     * @param  array<string, mixed>  $fields
     */
    public static function fromLoginWidget(array $fields): static
    {
        return new static(
            (int) $fields['id'],
            (string) ($fields['first_name'] ?? ''),
            $fields['last_name'] ?? null,
            $fields['username'] ?? null,
            null,
            $fields['photo_url'] ?? null,
            false,
            (int) ($fields['auth_date'] ?? 0),
            'login_widget',
            $fields,
        );
    }

    /**
     * Get the display name of the user.
     */
    public function name(): string
    {
        return trim($this->firstName.' '.($this->lastName ?? ''));
    }

    /**
     * Get the array form of the identity.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'first_name' => $this->firstName,
            'last_name' => $this->lastName,
            'username' => $this->username,
            'language_code' => $this->languageCode,
            'photo_url' => $this->photoUrl,
            'is_premium' => $this->isPremium,
            'auth_date' => $this->authDate,
            'source' => $this->source,
        ];
    }
}
