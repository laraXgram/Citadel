<?php

namespace LaraGram\Citadel\Contracts;

use DateTimeInterface;
use LaraGram\Contracts\Auth\Authenticatable;
use LaraGram\Database\Eloquent\Relations\HasMany;
use LaraGram\Database\Eloquent\Relations\MorphMany;

interface HasApiTokens extends Authenticatable
{
    /**
     * Get the personal access tokens that belong to the model.
     */
    public function tokens(): MorphMany;

    /**
     * Get the OAuth access tokens issued to the model.
     */
    public function oauthTokens(): HasMany;

    /**
     * Get the OAuth clients owned by the model.
     */
    public function oauthApps(): MorphMany;

    /**
     * Determine if the current access token has a given ability (or scope).
     */
    public function tokenCan(string $ability): bool;

    /**
     * Determine if the current access token is missing a given ability (or scope).
     */
    public function tokenCant(string $ability): bool;

    /**
     * Create a new personal access token for the model.
     *
     * @param  string[]  $abilities
     */
    public function createToken(string $name, array $abilities = ['*'], ?DateTimeInterface $expiresAt = null): \LaraGram\Citadel\NewAccessToken;

    /**
     * Get the access token currently associated with the model.
     */
    public function currentAccessToken(): ?HasAbilities;

    /**
     * Set the current access token for the model.
     */
    public function withAccessToken(?HasAbilities $accessToken): static;

    /**
     * Get the user provider name of the model.
     */
    public function getProviderName(): string;
}
