<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Auth\AuthenticationException;
use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\Client;
use LaraGram\Citadel\ClientRepository;
use LaraGram\Citadel\Contracts\AuthorizationViewResponse;
use LaraGram\Citadel\OAuth\AuthorizationRequest;
use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Contracts\Auth\Authenticatable;
use LaraGram\Contracts\Auth\StatefulGuard;
use LaraGram\Http\BaseResponse as Response;
use LaraGram\Http\Request;
use LaraGram\Support\Facades\Date;
use LaraGram\Support\Str;

class AuthorizationController
{
    use HandlesOAuthErrors;

    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected AuthorizationServer $server,
        protected StatefulGuard $guard,
        protected ClientRepository $clients,
    ) {
    }

    /**
     * Authorize a client to access the user's account.
     *
     * @throws \LaraGram\Auth\AuthenticationException
     */
    public function authorize(Request $request, AuthorizationViewResponse $viewResponse): Response|AuthorizationViewResponse
    {
        $authRequest = $this->withErrorHandling(
            fn () => $this->server->validateAuthorizationRequest($request),
            $request->query('response_type') === 'token'
        );

        $prompt = $request->string('prompt')->explode(' ')->map(trim(...))->filter()->values();

        // If the prompt parameter includes "none", all other prompt values will be ignored.
        // An error will be returned if the end-user is not already authenticated or the
        // OAuth client does not have pre-configured consent for the requested scopes.
        if ($prompt->contains('none')) {
            $prompt = collect(['none']);
        }

        if ($this->guard->guest()) {
            $prompt->contains('none')
                ? $this->throwOAuthError(OAuthServerException::loginRequired($authRequest), $authRequest)
                : $this->promptForLogin($request);
        }

        if ($prompt->contains('login') &&
            ! $request->session()->get('promptedForLogin', false)) {
            $this->guard->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
            $this->promptForLogin($request);
        }

        $request->session()->forget('promptedForLogin');

        $user = $this->guard->user();

        $authRequest->setUser($user->getAuthIdentifier());

        $scopes = Citadel::scopesFor($authRequest->scopes);

        $client = $this->clients->find($authRequest->clientId);

        if ($prompt->doesntContain('consent') &&
            ($client->skipsAuthorization($user, $scopes) || $this->hasGrantedScopes($user, $client, $scopes))) {
            return $this->approveRequest($authRequest);
        }

        if ($prompt->contains('none')) {
            $this->throwOAuthError(OAuthServerException::consentRequired($authRequest), $authRequest);
        }

        $request->session()->put('authToken', $authToken = Str::random());
        $request->session()->put('authRequest', $authRequest->toArray());

        return $viewResponse->withParameters([
            'client' => $client,
            'user' => $user,
            'scopes' => $scopes,
            'request' => $request,
            'authToken' => $authToken,
        ]);
    }

    /**
     * Determine if the given user has already granted the client access to the scopes.
     *
     * @param  \LaraGram\Citadel\Scope[]  $scopes
     */
    protected function hasGrantedScopes(Authenticatable $user, Client $client, array $scopes): bool
    {
        $activeTokens = $client->tokens()->where([
            ['user_id', '=', $user->getAuthIdentifier()],
            ['revoked', '=', false],
            ['expires_at', '>', Date::now()],
        ]);

        // If no specific scope is requested, we'll simply check whether the given
        // user has any active tokens that grant access to the specified client.
        if (empty($scopes)) {
            return $activeTokens->exists();
        }

        // Otherwise, we list all previously granted scopes from the active tokens
        // of the given user that authorize access to the specified client, and
        // check whether the newly requested scopes are included in that set.
        return collect($scopes)->pluck('id')->diff(
            $activeTokens->pluck('scopes')->flatten()
        )->isEmpty();
    }

    /**
     * Approve the authorization request.
     */
    protected function approveRequest(AuthorizationRequest $authRequest): Response
    {
        $authRequest->setAuthorizationApproved(true);

        return $this->withErrorHandling(
            fn () => $this->server->completeAuthorizationRequest($authRequest),
            $authRequest->grantTypeId === 'implicit'
        );
    }

    /**
     * Throw the given OAuth error for the authorization request.
     */
    protected function throwOAuthError(OAuthServerException $e, AuthorizationRequest $authRequest): never
    {
        $this->withErrorHandling(fn () => throw $e, $authRequest->grantTypeId === 'implicit');

        throw $e;
    }

    /**
     * Prompt the user to login by throwing an AuthenticationException.
     *
     * @throws \LaraGram\Auth\AuthenticationException
     */
    protected function promptForLogin(Request $request): never
    {
        $request->session()->put('promptedForLogin', true);

        throw new AuthenticationException(guards: isset($this->guard->name) ? [$this->guard->name] : []);
    }
}
