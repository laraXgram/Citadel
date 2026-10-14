<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Http\BaseResponse as Response;
use LaraGram\Http\Request;

class DenyAuthorizationController
{
    use HandlesOAuthErrors, RetrievesAuthRequestFromSession;

    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected AuthorizationServer $server,
    ) {
    }

    /**
     * Deny the authorization request.
     */
    public function deny(Request $request): Response
    {
        $authRequest = $this->getAuthRequestFromSession($request);

        $authRequest->setAuthorizationApproved(false);

        return $this->withErrorHandling(
            fn () => $this->server->completeAuthorizationRequest($authRequest),
            $authRequest->grantTypeId === 'implicit'
        );
    }
}
