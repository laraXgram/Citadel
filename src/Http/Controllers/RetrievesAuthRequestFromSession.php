<?php

namespace LaraGram\Citadel\Http\Controllers;

use Exception;
use LaraGram\Citadel\Exceptions\InvalidAuthTokenException;
use LaraGram\Citadel\OAuth\AuthorizationRequest;
use LaraGram\Http\Request;

trait RetrievesAuthRequestFromSession
{
    /**
     * Get the authorization request from the session.
     *
     * @throws \LaraGram\Citadel\Exceptions\InvalidAuthTokenException
     * @throws \Exception
     */
    protected function getAuthRequestFromSession(Request $request): AuthorizationRequest
    {
        if ($request->isNotFilled('auth_token') ||
            $request->session()->pull('authToken') !== $request->input('auth_token')) {
            $request->session()->forget(['authToken', 'authRequest']);

            throw InvalidAuthTokenException::different();
        }

        $authRequest = $request->session()->pull('authRequest')
            ?? throw new Exception('Authorization request was not present in the session.');

        return AuthorizationRequest::fromArray($authRequest);
    }
}
