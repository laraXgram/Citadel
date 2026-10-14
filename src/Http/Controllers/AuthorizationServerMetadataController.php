<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\Citadel;
use LaraGram\Http\JsonResponse;

class AuthorizationServerMetadataController
{
    /**
     * Get the authorization server metadata (RFC 8414).
     */
    public function __invoke(): JsonResponse
    {
        return new JsonResponse(Citadel::authorizationServerMetadata(), 200, [
            'Cache-Control' => 'public, max-age=3600',
        ]);
    }
}
