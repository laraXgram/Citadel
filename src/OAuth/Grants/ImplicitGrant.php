<?php

namespace LaraGram\Citadel\OAuth\Grants;

use DateInterval;
use LaraGram\Citadel\OAuth\AuthorizationRequest;
use LaraGram\Citadel\OAuth\BearerTokenResponse;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Http\RedirectResponse;
use LaraGram\Http\Request;
use LogicException;

/**
 * The legacy implicit grant (RFC 6749 section 4.2). Disabled unless enabled explicitly.
 */
class ImplicitGrant extends AbstractGrant
{
    use ValidatesAuthorizationRequests;

    /**
     * Get the grant type identifier.
     */
    public function getIdentifier(): string
    {
        return 'implicit';
    }

    /**
     * The implicit grant never answers the token endpoint.
     */
    public function canRespondToAccessTokenRequest(Request $request): bool
    {
        return false;
    }

    /**
     * Respond to an access token request.
     */
    public function respondToAccessTokenRequest(Request $request, DateInterval $accessTokenTTL): BearerTokenResponse
    {
        throw new LogicException('The implicit grant can not be used to issue tokens from the token endpoint.');
    }

    /**
     * Determine if the grant can respond to the given authorization request.
     */
    public function canRespondToAuthorizationRequest(Request $request): bool
    {
        return $request->query('response_type') === 'token' && $request->query('client_id') !== null;
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

        return new AuthorizationRequest($this->getIdentifier(), (string) $client->getKey(), $redirectUri, $scopes, $state);
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

        $client = $this->getClientOrFail($authRequest->clientId);

        $response = $this->respondWithTokens(
            $accessTokenTTL, $client, $authRequest->userId, $this->finalizeScopes($authRequest->scopes, $client), false
        );

        return new RedirectResponse(AuthorizationRequest::appendToUri($authRequest->redirectUri, [
            'access_token' => $response->jwt,
            'token_type' => 'Bearer',
            'expires_in' => $response->expiresIn,
            'state' => $authRequest->state,
        ], '#'));
    }
}
