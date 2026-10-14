<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\Contracts\ApprovedDeviceAuthorizationResponse;
use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Http\Request;

class ApproveDeviceAuthorizationController
{
    use HandlesOAuthErrors, RetrievesDeviceCodeFromSession;

    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected AuthorizationServer $server,
    ) {
    }

    /**
     * Approve the device authorization request.
     */
    public function __invoke(Request $request, ApprovedDeviceAuthorizationResponse $response): ApprovedDeviceAuthorizationResponse
    {
        $deviceCode = $this->getDeviceCodeFromSession($request);

        $this->withErrorHandling(fn () => $this->server->completeDeviceAuthorizationRequest(
            $deviceCode,
            $request->user()->getAuthIdentifier(),
            true
        ));

        return $response;
    }
}
