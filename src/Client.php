<?php

namespace LaraGram\Citadel;

use LaraGram\Citadel\Database\Factories\ClientFactory;
use LaraGram\Contracts\Auth\Authenticatable;
use LaraGram\Database\Eloquent\Casts\Attribute;
use LaraGram\Database\Eloquent\Concerns\HasUuids;
use LaraGram\Database\Eloquent\Factories\Factory;
use LaraGram\Database\Eloquent\Factories\HasFactory;
use LaraGram\Database\Eloquent\Model;
use LaraGram\Database\Eloquent\Relations\HasMany;
use LaraGram\Database\Eloquent\Relations\MorphTo;

/**
 * @property string|int $id
 * @property string $name
 * @property string|null $secret
 * @property string|null $plain_secret
 * @property string|null $provider
 * @property string[] $redirect_uris
 * @property string[] $grant_types
 * @property string[]|null $scopes
 * @property bool $revoked
 */
class Client extends Model
{
    use HasFactory;
    use HasUuids;
    use ResolvesInheritedScopes;

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'oauth_clients';

    /**
     * The guarded attributes on the model.
     *
     * @var array<string>|bool
     */
    protected $guarded = false;

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array<string>
     */
    protected $hidden = [
        'secret',
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'grant_types' => 'array',
        'scopes' => 'array',
        'redirect_uris' => 'array',
        'revoked' => 'bool',
    ];

    /**
     * The temporary plain-text client secret.
     *
     * This is only available once during the request that created the client.
     */
    public ?string $plainSecret = null;

    /**
     * Initialize the trait.
     */
    public function initializeHasUniqueStringIds(): void
    {
        $this->usesUniqueIds = Citadel::$clientUuids;
    }

    /**
     * Get the user (or any other model) that owns the client.
     */
    public function owner(): MorphTo
    {
        return $this->morphTo('owner');
    }

    /**
     * Get all of the authentication codes for the client.
     *
     * @return \LaraGram\Database\Eloquent\Relations\HasMany<\LaraGram\Citadel\AuthCode, $this>
     */
    public function authCodes(): HasMany
    {
        return $this->hasMany(Citadel::authCodeModel(), 'client_id');
    }

    /**
     * Get all of the tokens that belong to the client.
     *
     * @return \LaraGram\Database\Eloquent\Relations\HasMany<\LaraGram\Citadel\Token, $this>
     */
    public function tokens(): HasMany
    {
        return $this->hasMany(Citadel::tokenModel(), 'client_id');
    }

    /**
     * Interact with the client's secret, hashing it and keeping the plain-text value.
     */
    protected function secret(): Attribute
    {
        return Attribute::make(
            set: function (?string $value): ?string {
                $this->plainSecret = $value;

                return $this->castAttributeAsHashedString('secret', $value);
            },
        );
    }

    /**
     * Get the client's plain-text secret.
     */
    protected function plainSecret(): Attribute
    {
        return Attribute::make(
            get: fn (): ?string => $this->plainSecret
        );
    }

    /**
     * Determine if the client is a "first party" client.
     */
    public function firstParty(): bool
    {
        return empty($this->owner_id);
    }

    /**
     * Determine if the client should skip the authorization prompt.
     *
     * @param  \LaraGram\Citadel\Scope[]  $scopes
     */
    public function skipsAuthorization(Authenticatable $user, array $scopes): bool
    {
        return false;
    }

    /**
     * Determine if the client has the given grant type.
     */
    public function hasGrantType(string $grantType): bool
    {
        return in_array($grantType, $this->grant_types ?? [], true);
    }

    /**
     * Determine whether the client has the given scope (a null list allows every scope).
     */
    public function hasScope(string $scope): bool
    {
        return ! isset($this->attributes['scopes']) || $this->grants($scope, (array) $this->scopes);
    }

    /**
     * Determine if the client is a confidential client.
     */
    public function confidential(): bool
    {
        return ! empty($this->getAttributes()['secret'] ?? null);
    }

    /**
     * Determine if the given redirect URI is registered for the client.
     *
     * Loopback redirects (RFC 8252) match on any port, as native apps pick one at runtime.
     */
    public function allowsRedirectUri(string $uri): bool
    {
        foreach ($this->redirect_uris ?? [] as $registered) {
            if (hash_equals($registered, $uri)) {
                return true;
            }

            if ($this->isLoopback($registered) && $this->isLoopback($uri)
                && $this->withoutPort($registered) === $this->withoutPort($uri)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the URI points to the loopback interface over plain HTTP.
     */
    protected function isLoopback(string $uri): bool
    {
        return parse_url($uri, PHP_URL_SCHEME) === 'http'
            && in_array(parse_url($uri, PHP_URL_HOST), ['127.0.0.1', '[::1]', 'localhost'], true);
    }

    /**
     * Remove the port from the given URI.
     */
    protected function withoutPort(string $uri): string
    {
        $parts = parse_url($uri);

        return ($parts['scheme'] ?? '').'://'.($parts['host'] ?? '').($parts['path'] ?? '').(isset($parts['query']) ? '?'.$parts['query'] : '');
    }

    /**
     * Get the current connection name for the model.
     */
    public function getConnectionName(): ?string
    {
        return parent::getConnectionName() ?? config('citadel.connection');
    }

    /**
     * Create a new factory instance for the model.
     */
    protected static function newFactory(): Factory
    {
        return ClientFactory::new();
    }
}
