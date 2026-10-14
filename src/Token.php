<?php

namespace LaraGram\Citadel;

use LaraGram\Citadel\Contracts\HasAbilities;
use LaraGram\Database\Eloquent\Model;
use LaraGram\Database\Eloquent\Relations\BelongsTo;
use LaraGram\Database\Eloquent\Relations\HasOne;

class Token extends Model implements HasAbilities
{
    use ResolvesInheritedScopes;

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'oauth_access_tokens';

    /**
     * The "type" of the primary key ID.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * Indicates if the IDs are auto-incrementing.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * The guarded attributes on the model.
     *
     * @var array<string>|bool
     */
    protected $guarded = false;

    /**
     * The attributes that should be cast to native types.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'scopes' => 'array',
        'revoked' => 'bool',
        'expires_at' => 'datetime',
    ];

    /**
     * Get the client that the token belongs to.
     *
     * @return \LaraGram\Database\Eloquent\Relations\BelongsTo<\LaraGram\Citadel\Client, $this>
     */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Citadel::clientModel());
    }

    /**
     * Get the refresh token associated with the token.
     *
     * @return \LaraGram\Database\Eloquent\Relations\HasOne<\LaraGram\Citadel\RefreshToken, $this>
     */
    public function refreshToken(): HasOne
    {
        return $this->hasOne(Citadel::refreshTokenModel(), 'access_token_id');
    }

    /**
     * Get the user that the token belongs to.
     */
    public function user(): BelongsTo
    {
        $provider = $this->client?->provider ?: Citadel::defaultProvider();

        $model = config('auth.providers.'.$provider.'.model');

        return $this->belongsTo($model, 'user_id', (new $model)->getAuthIdentifierName());
    }

    /**
     * Determine if the token has a given scope.
     */
    public function can(string $ability): bool
    {
        if (empty($this->scopes)) {
            return false;
        }

        return $this->grants($ability, $this->scopes);
    }

    /**
     * Determine if the token is missing a given scope.
     */
    public function cant(string $ability): bool
    {
        return ! $this->can($ability);
    }

    /**
     * Revoke the token instance.
     */
    public function revoke(): bool
    {
        return $this->forceFill(['revoked' => true])->save();
    }

    /**
     * Get the current connection name for the model.
     */
    public function getConnectionName(): ?string
    {
        return parent::getConnectionName() ?? config('citadel.connection');
    }
}
