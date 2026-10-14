<?php

namespace LaraGram\Citadel\OAuth;

use LaraGram\Contracts\Support\Arrayable;

/**
 * A validated authorization request, waiting for the user's decision.
 *
 * It is stored in the session as a plain array between the consent screen
 * and the approval, so no object is ever unserialized from the session.
 */
class AuthorizationRequest implements Arrayable
{
    /**
     * Create a new authorization request.
     *
     * @param  string[]  $scopes
     */
    public function __construct(
        public string $grantTypeId,
        public string $clientId,
        public string $redirectUri,
        public array $scopes = [],
        public ?string $state = null,
        public ?string $codeChallenge = null,
        public ?string $codeChallengeMethod = null,
        public ?string $resource = null,
        public ?string $userId = null,
        public bool $approved = false,
    ) {
        //
    }

    /**
     * Restore an authorization request from its array form.
     *
     * @param  array<string, mixed>  $attributes
     */
    public static function fromArray(array $attributes): static
    {
        return new static(
            (string) $attributes['grant_type'],
            (string) $attributes['client_id'],
            (string) $attributes['redirect_uri'],
            (array) ($attributes['scopes'] ?? []),
            $attributes['state'] ?? null,
            $attributes['code_challenge'] ?? null,
            $attributes['code_challenge_method'] ?? null,
            $attributes['resource'] ?? null,
            isset($attributes['user_id']) ? (string) $attributes['user_id'] : null,
            (bool) ($attributes['approved'] ?? false),
        );
    }

    /**
     * Set the user that is answering the request.
     */
    public function setUser(string|int $userId): static
    {
        $this->userId = (string) $userId;

        return $this;
    }

    /**
     * Set whether the user approved the request.
     */
    public function setAuthorizationApproved(bool $approved): static
    {
        $this->approved = $approved;

        return $this;
    }

    /**
     * Get the array form of the request.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'grant_type' => $this->grantTypeId,
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scopes' => $this->scopes,
            'state' => $this->state,
            'code_challenge' => $this->codeChallenge,
            'code_challenge_method' => $this->codeChallengeMethod,
            'resource' => $this->resource,
            'user_id' => $this->userId,
            'approved' => $this->approved,
        ];
    }

    /**
     * Append parameters to the query string (or fragment) of a URI.
     *
     * @param  array<string, mixed>  $parameters
     */
    public static function appendToUri(string $uri, array $parameters, string $separator = '?'): string
    {
        $parameters = array_filter($parameters, fn ($value) => $value !== null);

        if ($parameters === []) {
            return $uri;
        }

        $glue = $separator === '?' && str_contains($uri, '?') ? '&' : $separator;

        if ($separator === '#' && str_contains($uri, '#')) {
            $glue = '&';
        }

        return $uri.$glue.http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}
