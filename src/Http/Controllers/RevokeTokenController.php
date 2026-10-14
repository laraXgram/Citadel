<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Http\Request;
use LaraGram\Http\Response;

class RevokeTokenController
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
     * Revoke an access or refresh token (RFC 7009).
     */
    public function __invoke(Request $request): Response
    {
        return $this->withErrorHandling(fn () => $this->server->revokeToken($request));
    }
}
