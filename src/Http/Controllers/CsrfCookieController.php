<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Http\JsonResponse;
use LaraGram\Http\Request;
use LaraGram\Http\Response;

class CsrfCookieController
{
    /**
     * Return an empty response simply to trigger the storage of the CSRF cookie in the browser.
     */
    public function show(Request $request): Response|JsonResponse
    {
        if ($request->expectsJson()) {
            return new JsonResponse(status: 204);
        }

        return new Response(status: 204);
    }
}
