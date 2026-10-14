<?php

namespace LaraGram\Citadel;

use JsonSerializable;
use LaraGram\Citadel\Contracts\HasAbilities;
use LaraGram\Contracts\Support\Arrayable;
use LaraGram\Contracts\Support\Jsonable;
use LaraGram\Support\Traits\ForwardsCalls;

/**
 * A validated OAuth access token.
 *
 * @property string|null $oauth_access_token_id
 * @property string|null $oauth_client_id
 * @property string|null $oauth_user_id
 * @property string[] $oauth_scopes
 *
 * @mixin \LaraGram\Citadel\Token
 */
class AccessToken implements HasAbilities, Arrayable, Jsonable, JsonSerializable
{
    use ResolvesInheritedScopes, ForwardsCalls;

    /**
     * The token instance.
     */
    protected ?Token $token = null;

    /**
     * All the attributes set on the access token instance.
     *
     * @var array<string, mixed>
     */
    protected array $attributes = [];

    /**
     * Create a new access token instance.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(array $attributes = [])
    {
        foreach ($attributes as $key => $value) {
            $this->attributes[$key] = $value;
        }
    }

    /**
     * Determine if the token has a given scope.
     */
    public function can(string $ability): bool
    {
        if (empty($this->attributes['oauth_scopes'])) {
            return false;
        }

        return $this->grants($ability, $this->attributes['oauth_scopes']);
    }

    /**
     * Determine if the token is missing a given scope.
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
     * Revoke the token instance.
     */
    public function revoke(): bool
    {
        if ($this->token) {
            return $this->token->revoke();
        }

        if (isset($this->attributes['oauth_access_token_id'])) {
            return (bool) Citadel::token()->newQuery()->whereKey($this->attributes['oauth_access_token_id'])->update(['revoked' => true]);
        }

        return false;
    }

    /**
     * Get the token instance.
     */
    protected function getToken(): ?Token
    {
        if ($this->token) {
            return $this->token;
        }

        if (isset($this->attributes['oauth_access_token_id'])) {
            return $this->token = Citadel::token()->newQuery()->find($this->attributes['oauth_access_token_id']);
        }

        return null;
    }

    /**
     * Get the instance as an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->attributes;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Convert the object to its JSON representation.
     *
     * @param  int  $options
     */
    public function toJson($options = 0): string
    {
        return json_encode($this->jsonSerialize(), $options);
    }

    /**
     * Determine if the given key is set on the token.
     */
    public function __isset(string $key): bool
    {
        return isset($this->attributes[$key]) || isset($this->getToken()?->{$key});
    }

    /**
     * Dynamically retrieve the value of an attribute.
     */
    public function __get(string $key): mixed
    {
        if (array_key_exists($key, $this->attributes)) {
            return $this->attributes[$key];
        }

        return $this->getToken()?->{$key};
    }

    /**
     * Pass dynamic methods onto the token instance.
     *
     * @param  array<int, mixed>  $parameters
     */
    public function __call(string $method, array $parameters): mixed
    {
        return $this->forwardCallTo($this->getToken(), $method, $parameters);
    }
}
