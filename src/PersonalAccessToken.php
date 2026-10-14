<?php

namespace LaraGram\Citadel;

use LaraGram\Citadel\Contracts\HasAbilities;
use LaraGram\Database\Eloquent\Model;
use LaraGram\Database\Eloquent\Relations\MorphTo;

class PersonalAccessToken extends Model implements HasAbilities
{
    use ResolvesInheritedScopes;

    /**
     * The attributes that should be cast to native types.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'abilities' => 'json',
        'last_used_at' => 'datetime',
        'expires_at' => 'datetime',
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'token',
        'abilities',
        'expires_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'token',
    ];

    /**
     * Get the tokenable model that the access token belongs to.
     */
    public function tokenable(): MorphTo
    {
        return $this->morphTo('tokenable');
    }

    /**
     * Find the token instance matching the given plain-text token.
     */
    public static function findToken(string $token): ?static
    {
        if (! str_contains($token, '|')) {
            return static::where('token', hash('sha256', $token))->first();
        }

        [$id, $token] = explode('|', $token, 2);

        if ($instance = static::find($id)) {
            return hash_equals($instance->token, hash('sha256', $token)) ? $instance : null;
        }

        return null;
    }

    /**
     * Determine if the token has a given ability.
     */
    public function can(string $ability): bool
    {
        return $this->grants($ability, (array) $this->abilities);
    }

    /**
     * Determine if the token is missing a given ability.
     */
    public function cant(string $ability): bool
    {
        return ! $this->can($ability);
    }

    /**
     * Determine if the token is a transient token.
     */
    public function transient(): bool
    {
        return false;
    }

    /**
     * Revoke the token.
     */
    public function revoke(): bool
    {
        return (bool) $this->delete();
    }

    /**
     * Get the current connection name for the model.
     */
    public function getConnectionName(): ?string
    {
        return parent::getConnectionName() ?? config('citadel.connection');
    }
}
