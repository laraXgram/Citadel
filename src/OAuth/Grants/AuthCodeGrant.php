<?php

namespace LaraGram\Citadel\OAuth\Grants;

use DateInterval;
use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\OAuth\AuthorizationRequest;
use LaraGram\Citadel\OAuth\BearerTokenResponse;
use LaraGram\Citadel\OAuth\Jwt;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Http\RedirectResponse;
use LaraGram\Http\Request;
use LaraGram\Support\Facades\Date;
use LogicException;

/**
 * The authorization code grant (RFC 6749 section 4.1) with PKCE (RFC 7636).
 */
class AuthCodeGrant extends AbstractGrant
{
    use ValidatesAuthorizationRequests;

    /**
     * Create a new authorization code grant.
     */
    public function __construct(
        protected DateInterval $authCodeTTL,
        protected bool $requireCodeChallengeForPublicClients = true,
    ) {
        //
    }

    /**
     * Get the grant type identifier.
     */
    public function getIdentifier(): string
    {
        return 'authorization_code';
    }

    /**
     * Determine if the grant can respond to the given authorization request.
     */
    public function canRespondToAuthorizationRequest(Request $request): bool
    {
        return $request->query('response_type') === 'code' && $request->query('client_id') !== null;
    }

    /**
     * Validate an authorization request.
     */
    public function validateAuthorizationRequest(Request $request): AuthorizationRequest
    {
        [$client, $redirectUri] = $this->validateClientAndRedirectUri($request);

        $state = $request->query('state');
        $state = is_string($state) ? $state : null;

        try {
            $scopes = $this->validateScopes($request->query('scope', $this->defaultScope), $redirectUri);
        } catch (OAuthServerException $e) {
            throw $e->withRedirectUri($redirectUri, $state);
        }

        $codeChallenge = $request->query('code_challenge');
        $codeChallengeMethod = null;

        if (is_string($codeChallenge) && $codeChallenge !== '') {
            $codeChallengeMethod = (string) $request->query('code_challenge_method', 'plain');

            if (! in_array($codeChallengeMethod, ['S256', 'plain'], true)) {
                throw OAuthServerException::invalidRequest('code_challenge_method', 'Code challenge method must be one of `S256`, `plain`')
                    ->withRedirectUri($redirectUri, $state);
            }

            if (! preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $codeChallenge)) {
                throw OAuthServerException::invalidRequest('code_challenge', 'Code challenge must follow the specifications of RFC-7636.')
                    ->withRedirectUri($redirectUri, $state);
            }
        } elseif ($this->requireCodeChallengeForPublicClients && ! $client->confidential()) {
            throw OAuthServerException::invalidRequest('code_challenge', 'Code challenge must be provided for public clients')
                ->withRedirectUri($redirectUri, $state);
        } else {
            $codeChallenge = null;
        }

        $resource = $request->query('resource');

        return new AuthorizationRequest(
            $this->getIdentifier(),
            (string) $client->getKey(),
            $redirectUri,
            $scopes,
            $state,
            $codeChallenge,
            $codeChallengeMethod,
            is_string($resource) ? $resource : null,
        );
    }

    /**
     * Complete an authorization request once the user decided.
     */
    public function completeAuthorizationRequest(AuthorizationRequest $authRequest, DateInterval $accessTokenTTL): RedirectResponse
    {
        if (is_null($authRequest->userId)) {
            throw new LogicException('A user must be set on the authorization request.');
        }

        if (! $authRequest->approved) {
            throw OAuthServerException::accessDenied('The user denied the request')
                ->withRedirectUri($authRequest->redirectUri, $authRequest->state);
        }

        $expiresAt = Date::now()->add($this->authCodeTTL);

        $authCode = Citadel::authCode()->forceFill([
            'id' => $this->generateUniqueIdentifier(),
            'user_id' => $authRequest->userId,
            'client_id' => $authRequest->clientId,
            'scopes' => $authRequest->scopes,
            'revoked' => false,
            'expires_at' => $expiresAt,
        ]);

        $authCode->save();

        $code = $this->encrypt([
            'client_id' => $authRequest->clientId,
            'redirect_uri' => $authRequest->redirectUri,
            'auth_code_id' => $authCode->getKey(),
            'scopes' => $authRequest->scopes,
            'user_id' => $authRequest->userId,
            'expire_time' => $expiresAt->getTimestamp(),
            'code_challenge' => $authRequest->codeChallenge,
            'code_challenge_method' => $authRequest->codeChallengeMethod,
        ]);

        return new RedirectResponse(AuthorizationRequest::appendToUri($authRequest->redirectUri, [
            'code' => $code,
            'state' => $authRequest->state,
        ]));
    }

    /**
     * Respond to an access token request.
     */
    public function respondToAccessTokenRequest(Request $request, DateInterval $accessTokenTTL): BearerTokenResponse
    {
        $client = $this->validateClient($request);

        $encrypted = $this->stringParameter($request, 'code');

        if (blank($encrypted)) {
            throw OAuthServerException::invalidRequest('code');
        }

        $payload = $this->decrypt($encrypted);

        if (! isset($payload['auth_code_id'], $payload['client_id'], $payload['expire_time'])) {
            throw OAuthServerException::invalidRequest('code', 'Cannot decrypt the authorization code');
        }

        if (time() > (int) $payload['expire_time']) {
            throw OAuthServerException::invalidGrant('Authorization code has expired');
        }

        $authCode = Citadel::authCode()->newQuery()->whereKey($payload['auth_code_id'])->first();

        if (! $authCode || $authCode->revoked) {
            throw OAuthServerException::invalidGrant('Authorization code has been revoked');
        }

        if ((string) $payload['client_id'] !== (string) $client->getKey()) {
            throw OAuthServerException::invalidRequest('code', 'Authorization code was not issued to this client');
        }

        $redirectUri = $this->stringParameter($request, 'redirect_uri');

        if (! empty($payload['redirect_uri'])) {
            if (is_null($redirectUri)) {
                throw OAuthServerException::invalidRequest('redirect_uri');
            }

            if ($payload['redirect_uri'] !== $redirectUri) {
                throw OAuthServerException::invalidClient('Invalid redirect URI');
            }
        }

        $this->verifyCodeChallenge($request, $payload);

        $authCode->forceFill(['revoked' => true])->save();

        return $this->respondWithTokens(
            $accessTokenTTL,
            $client,
            $payload['user_id'] ?? null,
            $this->finalizeScopes((array) ($payload['scopes'] ?? []), $client),
        );
    }

    /**
     * Verify the PKCE code verifier against the challenge of the code.
     *
     * @param  array<string, mixed>  $payload
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    protected function verifyCodeChallenge(Request $request, array $payload): void
    {
        $verifier = $this->stringParameter($request, 'code_verifier');

        if (empty($payload['code_challenge'])) {
            if (! is_null($verifier)) {
                throw OAuthServerException::invalidRequest('code_verifier', 'Failed to verify `code_verifier`.');
            }

            return;
        }

        if (is_null($verifier)) {
            throw OAuthServerException::invalidRequest('code_verifier');
        }

        if (! preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $verifier)) {
            throw OAuthServerException::invalidRequest('code_verifier', 'Code Verifier must follow the specifications of RFC-7636.');
        }

        $expected = match ($payload['code_challenge_method'] ?? 'plain') {
            'S256' => Jwt::base64UrlEncode(hash('sha256', $verifier, true)),
            default => $verifier,
        };

        if (! hash_equals((string) $payload['code_challenge'], $expected)) {
            throw OAuthServerException::invalidGrant('Failed to verify `code_verifier`.');
        }
    }
}
