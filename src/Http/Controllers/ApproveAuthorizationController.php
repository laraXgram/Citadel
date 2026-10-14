<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Http\BaseResponse as Response;
use LaraGram\Http\Request;

class ApproveAuthorizationController
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
     * Approve the authorization request.
     */
    public function approve(Request $request): Response
    {
        $authRequest = $this->getAuthRequestFromSession($request);

        $authRequest->setAuthorizationApproved(true);

        return $this->withErrorHandling(
            fn () => $this->server->completeAuthorizationRequest($authRequest),
            $authRequest->grantTypeId === 'implicit'
        );
    }
}
