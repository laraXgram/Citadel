<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Http\JsonResponse;
use LaraGram\Http\Request;

class DeviceCodeController
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
     * Issue a new device code for the client (RFC 8628 section 3.1).
     */
    public function __invoke(Request $request): JsonResponse
    {
        return $this->withErrorHandling(fn () => $this->server->respondToDeviceAuthorizationRequest($request));
    }
}
