<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Http\JsonResponse;
use LaraGram\Http\Request;

class AccessTokenController
{
    use HandlesOAuthErrors;

    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected AuthorizationServer $server,
    ) {
    }

    /**
     * Issue an access token.
     */
    public function issueToken(Request $request): JsonResponse
    {
        return $this->withErrorHandling(fn () => $this->server->respondToAccessTokenRequest($request));
    }
}
