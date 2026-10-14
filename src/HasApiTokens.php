<?php

namespace LaraGram\Citadel;

use DateTimeInterface;
use LaraGram\Citadel\Contracts\HasAbilities;
use LaraGram\Database\Eloquent\Builder;
use LaraGram\Database\Eloquent\Relations\HasMany;
use LaraGram\Database\Eloquent\Relations\MorphMany;
use LaraGram\Support\Str;
use LogicException;

trait HasApiTokens
{
    /**
     * The access token the user is using for the current request.
     */
    protected ?HasAbilities $accessToken = null;

    /**
     * Get the personal access tokens that belong to the model.
     *
     * @return \LaraGram\Database\Eloquent\Relations\MorphMany<\LaraGram\Citadel\PersonalAccessToken, $this>
     */
    public function tokens(): MorphMany
    {
        return $this->morphMany(Citadel::personalAccessTokenModel(), 'tokenable');
    }

    /**
     * Get the OAuth access tokens issued to the model.
     *
     * @return \LaraGram\Database\Eloquent\Relations\HasMany<\LaraGram\Citadel\Token, $this>
     */
    public function oauthTokens(): HasMany
    {
        return $this->hasMany(Citadel::tokenModel(), 'user_id', $this->getAuthIdentifierName())
            ->where(function (Builder $query): void {
                $query->whereHas('client', function (Builder $query): void {
                    $query->where(function (Builder $query): void {
                        $provider = $this->getProviderName();

                        $query->when($provider === Citadel::defaultProvider(), function (Builder $query): void {
                            $query->orWhereNull('provider');
                        })->orWhere('provider', $provider);
                    });
                });
            });
    }

    /**
     * Get the OAuth clients owned by the model.
     *
     * @return \LaraGram\Database\Eloquent\Relations\MorphMany<\LaraGram\Citadel\Client, $this>
     */
    public function oauthApps(): MorphMany
    {
        return $this->morphMany(Citadel::clientModel(), 'owner');
    }

    /**
     * Determine if the current access token has a given ability (or scope).
     */
    public function tokenCan(string $ability): bool
    {
        return $this->accessToken && $this->accessToken->can($ability);
    }

    /**
     * Determine if the current access token is missing a given ability (or scope).
     */
    public function tokenCant(string $ability): bool
    {
        return ! $this->tokenCan($ability);
    }

    /**
     * Create a new personal access token for the model.
     *
     * @param  string[]  $abilities
     */
    public function createToken(string $name, array $abilities = ['*'], ?DateTimeInterface $expiresAt = null): NewAccessToken
    {
        $plainTextToken = $this->generateTokenString();

        $token = $this->tokens()->create([
            'name' => $name,
            'token' => hash('sha256', $plainTextToken),
            'abilities' => $abilities,
            'expires_at' => $expiresAt,
        ]);

        return new NewAccessToken($token, $token->getKey().'|'.$plainTextToken);
    }

    /**
     * Generate the token string.
     */
    public function generateTokenString(): string
    {
        return sprintf(
            '%s%s%s',
            config('citadel.token_prefix', ''),
            $tokenEntropy = Str::random(40),
            hash('crc32b', $tokenEntropy)
        );
    }

    /**
     * Get the access token currently associated with the user.
     *
     * @return \LaraGram\Citadel\Contracts\HasAbilities|null
     */
    public function currentAccessToken(): ?HasAbilities
    {
        return $this->accessToken;
    }

    /**
     * Get the access token currently associated with the user.
     */
    public function token(): ?HasAbilities
    {
        return $this->currentAccessToken();
    }

    /**
     * Set the current access token for the user.
     */
    public function withAccessToken(?HasAbilities $accessToken): static
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    /**
     * Get the user provider name of the model.
     */
    public function getProviderName(): string
    {
        $providers = collect(config('auth.guards'))->where('driver', 'citadel')->pluck('provider')->filter()
            ->push(Citadel::defaultProvider())
            ->filter()
            ->unique()
            ->all();

        foreach (config('auth.providers') as $provider => $config) {
            if (in_array($provider, $providers, true) && ($config['driver'] ?? null) === 'eloquent' && is_a($this, $config['model'])) {
                return $provider;
            }
        }

        throw new LogicException('Unable to determine authentication provider for this model from configuration.');
    }
}
