<?php

namespace LaraGram\Citadel;

use LaraGram\Contracts\Auth\Authenticatable;
use LaraGram\Database\Eloquent\Collection;
use LaraGram\Support\Str;

class ClientRepository
{
    /**
     * Get a client by the given ID.
     */
    public function find(string|int $id): ?Client
    {
        $client = Citadel::client();

        if (in_array($client->getKeyName(), $client->uniqueIds()) &&
            ! (fn () => $this->isValidUniqueId($id))->call($client)) {
            return null;
        }

        return once(fn () => Citadel::client()->newQuery()->find($id));
    }

    /**
     * Get an active client by the given ID.
     */
    public function findActive(string|int $id): ?Client
    {
        $client = $this->find($id);

        return $client && ! $client->revoked ? $client : null;
    }

    /**
     * Get a client instance owned by the given user.
     */
    public function findForUser(string|int $clientId, Authenticatable $user): ?Client
    {
        return $user->oauthApps()->where('revoked', false)->find($clientId);
    }

    /**
     * Get the active client instances owned by the given user.
     *
     * @return \LaraGram\Database\Eloquent\Collection<int, \LaraGram\Citadel\Client>
     */
    public function forUser(Authenticatable $user): Collection
    {
        return $user->oauthApps()->where('revoked', false)->orderBy('name')->get();
    }

    /**
     * Determine if the given secret matches the client's (hashed) secret.
     */
    public function validateSecret(Client $client, ?string $secret): bool
    {
        $hashed = $client->getAttributes()['secret'] ?? null;

        return ! empty($secret) && ! empty($hashed) && app('hash')->check($secret, $hashed);
    }

    /**
     * Store a new client.
     *
     * @param  string[]  $grantTypes
     * @param  string[]  $redirectUris
     * @param  string[]|null  $scopes
     */
    protected function create(
        string $name,
        array $grantTypes,
        array $redirectUris = [],
        ?string $provider = null,
        bool $confidential = true,
        ?Authenticatable $user = null,
        ?array $scopes = null,
    ): Client {
        $attributes = [
            'name' => $name,
            'secret' => $confidential ? Str::random(40) : null,
            'provider' => $provider,
            'redirect_uris' => $redirectUris,
            'grant_types' => $grantTypes,
            'scopes' => $scopes,
            'revoked' => false,
        ];

        return is_null($user)
            ? Citadel::client()->newQuery()->forceCreate($attributes)
            : $user->oauthApps()->forceCreate($attributes);
    }

    /**
     * Store a new password grant client.
     */
    public function createPasswordGrantClient(string $name, ?string $provider = null, bool $confidential = false): Client
    {
        return $this->create($name, ['password', 'refresh_token'], [], $provider, $confidential);
    }

    /**
     * Store a new client credentials grant client.
     *
     * @param  string[]|null  $scopes
     */
    public function createClientCredentialsGrantClient(string $name, ?array $scopes = null): Client
    {
        return $this->create($name, ['client_credentials'], scopes: $scopes);
    }

    /**
     * Store a new implicit grant client.
     *
     * @param  string[]  $redirectUris
     */
    public function createImplicitGrantClient(string $name, array $redirectUris): Client
    {
        return $this->create($name, ['implicit'], $redirectUris, null, false);
    }

    /**
     * Store a new device authorization grant client.
     */
    public function createDeviceAuthorizationGrantClient(
        string $name,
        bool $confidential = true,
        ?Authenticatable $user = null,
    ): Client {
        return $this->create(
            $name, ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'], [], null, $confidential, $user
        );
    }

    /**
     * Store a new authorization code grant client.
     *
     * @param  string[]  $redirectUris
     */
    public function createAuthorizationCodeGrantClient(
        string $name,
        array $redirectUris,
        bool $confidential = true,
        ?Authenticatable $user = null,
        bool $enableDeviceFlow = false,
    ): Client {
        $grantTypes = ['authorization_code', 'refresh_token'];

        if ($enableDeviceFlow) {
            $grantTypes[] = 'urn:ietf:params:oauth:grant-type:device_code';
        }

        return $this->create($name, $grantTypes, $redirectUris, null, $confidential, $user);
    }

    /**
     * Store a new Telegram grant client, for Mini Apps and Login Widget sign-ins.
     *
     * Telegram clients are public: the signed Telegram payload is the credential.
     */
    public function createTelegramGrantClient(string $name, ?string $provider = null): Client
    {
        return $this->create($name, ['telegram_init_data', 'telegram_login', 'refresh_token'], [], $provider, false);
    }

    /**
     * Update the given client.
     *
     * @param  string[]  $redirectUris
     */
    public function update(Client $client, string $name, array $redirectUris): bool
    {
        return $client->forceFill([
            'name' => $name,
            'redirect_uris' => $redirectUris,
        ])->save();
    }

    /**
     * Regenerate the client secret.
     */
    public function regenerateSecret(Client $client): bool
    {
        return $client->forceFill([
            'secret' => Str::random(40),
        ])->save();
    }

    /**
     * Delete the given client, revoking all of its tokens.
     */
    public function delete(Client $client): void
    {
        $client->tokens()->with('refreshToken')->each(function (Token $token): void {
            $token->refreshToken?->revoke();
            $token->revoke();
        });

        $client->forceFill(['revoked' => true])->save();
    }
}
