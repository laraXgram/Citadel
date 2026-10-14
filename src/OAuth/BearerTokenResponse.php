<?php

namespace LaraGram\Citadel\OAuth;

use LaraGram\Citadel\Token;
use LaraGram\Http\JsonResponse;

/**
 * The successful response of the token endpoint (RFC 6749 section 5.1).
 */
class BearerTokenResponse
{
    /**
     * Create a new bearer token response.
     */
    public function __construct(
        public Token $accessToken,
        public string $jwt,
        public int $expiresIn,
        public ?string $refreshToken = null,
    ) {
        //
    }

    /**
     * Get the response values.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_filter([
            'token_type' => 'Bearer',
            'expires_in' => $this->expiresIn,
            'access_token' => $this->jwt,
            'refresh_token' => $this->refreshToken,
            ...$this->getExtraParams($this->accessToken),
        ], fn ($value) => $value !== null);
    }

    /**
     * Add custom fields to the response.
     *
     * @return array<string, mixed>
     */
    protected function getExtraParams(Token $accessToken): array
    {
        return [];
    }

    /**
     * Build the HTTP response.
     */
    public function toResponse(): JsonResponse
    {
        return new JsonResponse($this->toArray(), 200, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }
}
