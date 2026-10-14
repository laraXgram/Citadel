<?php

namespace LaraGram\Citadel\OAuth;

use Exception;
use LaraGram\Http\JsonResponse;
use LaraGram\Http\RedirectResponse;
use LaraGram\Http\Request;
use Throwable;

/**
 * An OAuth 2 error response (RFC 6749 section 5.2 and RFC 8628 section 3.5).
 */
class OAuthServerException extends Exception
{
    /**
     * The extra values added to the error payload.
     *
     * @var array<string, mixed>
     */
    protected array $payload = [];

    /**
     * Create a new OAuth error.
     */
    public function __construct(
        string $message,
        protected string $errorType,
        protected int $httpStatusCode = 400,
        protected ?string $hint = null,
        protected ?string $redirectUri = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * Invalid request error.
     */
    public static function invalidRequest(string $parameter, ?string $hint = null, ?Throwable $previous = null): static
    {
        return new static(
            'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.',
            'invalid_request', 400, $hint ?? sprintf('Check the `%s` parameter', $parameter), null, $previous
        );
    }

    /**
     * Invalid client error.
     */
    public static function invalidClient(?string $hint = null): static
    {
        return new static('Client authentication failed', 'invalid_client', 401, $hint);
    }

    /**
     * Unauthorized client error.
     */
    public static function unauthorizedClient(?string $hint = null): static
    {
        return new static(
            'The authenticated client is not authorized to use this authorization grant type.',
            'unauthorized_client', 400, $hint
        );
    }

    /**
     * Unsupported grant type error.
     */
    public static function unsupportedGrantType(): static
    {
        return new static(
            'The authorization grant type is not supported by the authorization server.',
            'unsupported_grant_type', 400, 'Check that all required parameters have been provided'
        );
    }

    /**
     * Unsupported response type error.
     */
    public static function unsupportedResponseType(): static
    {
        return new static(
            'The authorization server does not support obtaining an authorization code using this method.',
            'unsupported_response_type', 400
        );
    }

    /**
     * Invalid scope error.
     */
    public static function invalidScope(string $scope, ?string $redirectUri = null): static
    {
        return new static(
            'The requested scope is invalid, unknown, or malformed',
            'invalid_scope', 400, sprintf('Check the `%s` scope', $scope), $redirectUri
        );
    }

    /**
     * Invalid credentials error.
     */
    public static function invalidCredentials(?string $hint = null): static
    {
        return new static('The user credentials were incorrect.', 'invalid_grant', 400, $hint);
    }

    /**
     * Server error.
     */
    public static function serverError(string $hint, ?Throwable $previous = null): static
    {
        return new static(
            'The authorization server encountered an unexpected condition which prevented it from fulfilling the request: '.$hint,
            'server_error', 500, null, null, $previous
        );
    }

    /**
     * Invalid refresh token error.
     */
    public static function invalidRefreshToken(?string $hint = null, ?Throwable $previous = null): static
    {
        return new static('The refresh token is invalid.', 'invalid_grant', 400, $hint, null, $previous);
    }

    /**
     * Access denied error.
     */
    public static function accessDenied(?string $hint = null, ?string $redirectUri = null, ?Throwable $previous = null): static
    {
        return new static(
            'The resource owner or authorization server denied the request.',
            'access_denied', 401, $hint, $redirectUri, $previous
        );
    }

    /**
     * Invalid grant error.
     */
    public static function invalidGrant(string $hint = ''): static
    {
        return new static(
            'The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.',
            'invalid_grant', 400, $hint
        );
    }

    /**
     * Expired device code error.
     */
    public static function expiredToken(?string $hint = null): static
    {
        return new static(
            'The `device_code` has expired and the device authorization session has concluded.',
            'expired_token', 400, $hint
        );
    }

    /**
     * Pending device authorization error.
     */
    public static function authorizationPending(?string $hint = null): static
    {
        return new static(
            'The authorization request is still pending as the end user hasn\'t yet completed the user-interaction steps.',
            'authorization_pending', 400, $hint
        );
    }

    /**
     * Polling too fast error.
     */
    public static function slowDown(?string $hint = null): static
    {
        return new static(
            'The authorization request is still pending and polling should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests.',
            'slow_down', 400, $hint
        );
    }

    /**
     * Login required error (OpenID Connect "prompt=none").
     */
    public static function loginRequired(AuthorizationRequest $authRequest): static
    {
        return (new static(
            'The authorization server requires end-user authentication.',
            'login_required', 401, 'The user is not authenticated', $authRequest->redirectUri
        ))->withPayload(['state' => $authRequest->state]);
    }

    /**
     * Consent required error (OpenID Connect "prompt=none").
     */
    public static function consentRequired(AuthorizationRequest $authRequest): static
    {
        return (new static(
            'The authorization server requires end-user consent.',
            'consent_required', 401, null, $authRequest->redirectUri
        ))->withPayload(['state' => $authRequest->state]);
    }

    /**
     * Add values to the error payload.
     *
     * @param  array<string, mixed>  $payload
     */
    public function withPayload(array $payload): static
    {
        $this->payload = array_merge($this->payload, $payload);

        return $this;
    }

    /**
     * Set the URI the error should be redirected to.
     */
    public function withRedirectUri(?string $redirectUri, ?string $state = null): static
    {
        $this->redirectUri = $redirectUri;

        return $state === null ? $this : $this->withPayload(['state' => $state]);
    }

    /**
     * Get the error payload.
     *
     * @return array<string, mixed>
     */
    public function getPayload(): array
    {
        return array_filter([
            'error' => $this->errorType,
            'error_description' => $this->getMessage(),
            'hint' => $this->hint ?: null,
            ...$this->payload,
        ], fn ($value) => $value !== null);
    }

    /**
     * Get the error type.
     */
    public function getErrorType(): string
    {
        return $this->errorType;
    }

    /**
     * Get the HTTP status code of the error.
     */
    public function getHttpStatusCode(): int
    {
        return $this->httpStatusCode;
    }

    /**
     * Get the hint of the error.
     */
    public function getHint(): ?string
    {
        return $this->hint;
    }

    /**
     * Determine if the error is redirected back to the client.
     */
    public function hasRedirect(): bool
    {
        return $this->redirectUri !== null;
    }

    /**
     * Build the HTTP response of the error.
     */
    public function toResponse(bool $useFragment = false, ?Request $request = null): JsonResponse|RedirectResponse
    {
        if ($this->redirectUri !== null) {
            return new RedirectResponse(
                AuthorizationRequest::appendToUri($this->redirectUri, $this->getPayload(), $useFragment ? '#' : '?')
            );
        }

        $response = new JsonResponse($this->getPayload(), $this->httpStatusCode, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);

        if ($this->errorType === 'invalid_client' && ($request ?? request())?->headers->has('Authorization')) {
            $response->headers->set('WWW-Authenticate', 'Basic realm="OAuth"');
        }

        return $response;
    }
}
