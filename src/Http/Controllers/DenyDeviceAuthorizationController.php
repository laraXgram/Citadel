<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\Contracts\DeniedDeviceAuthorizationResponse;
use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Http\Request;

class DenyDeviceAuthorizationController
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
     * Deny the device authorization request.
     */
    public function __invoke(Request $request, DeniedDeviceAuthorizationResponse $response): DeniedDeviceAuthorizationResponse
    {
        $deviceCode = $this->getDeviceCodeFromSession($request);

        $this->withErrorHandling(fn () => $this->server->completeDeviceAuthorizationRequest(
            $deviceCode,
            $request->user()->getAuthIdentifier(),
            false
        ));

        return $response;
    }
}
