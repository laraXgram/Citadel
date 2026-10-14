<?php

namespace LaraGram\Citadel;

use LaraGram\Database\Eloquent\Model;
use LaraGram\Database\Eloquent\Relations\BelongsTo;

class DeviceCode extends Model
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'oauth_device_codes';

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
     * Indicates if the model should be timestamped.
     *
     * @var bool
     */
    public $timestamps = false;

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
        'user_approved_at' => 'datetime',
        'last_polled_at' => 'datetime',
        'expires_at' => 'datetime',
    ];

    /**
     * Get the client that requested the device code.
     *
     * @return \LaraGram\Database\Eloquent\Relations\BelongsTo<\LaraGram\Citadel\Client, $this>
     */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Citadel::clientModel());
    }

    /**
     * Determine if the device code is still waiting for the user's decision.
     */
    public function pending(): bool
    {
        return ! $this->revoked
            && is_null($this->user_id)
            && ($this->expires_at === null || $this->expires_at->isFuture());
    }

    /**
     * Get the user code formatted for display ("ABCD-EFGH").
     */
    public function formattedUserCode(): string
    {
        return implode('-', str_split((string) $this->user_code, 4));
    }

    /**
     * Get the current connection name for the model.
     */
    public function getConnectionName(): ?string
    {
        return parent::getConnectionName() ?? config('citadel.connection');
    }
}
