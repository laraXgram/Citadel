<?php

namespace LaraGram\Citadel\Http\Controllers;

use Exception;
use LaraGram\Citadel\Exceptions\InvalidAuthTokenException;
use LaraGram\Http\Request;

trait RetrievesDeviceCodeFromSession
{
    /**
     * Get the ID of the device code being authorized from the session.
     *
     * @throws \LaraGram\Citadel\Exceptions\InvalidAuthTokenException
     * @throws \Exception
     */
    protected function getDeviceCodeFromSession(Request $request): string
    {
        if ($request->isNotFilled('auth_token') ||
            $request->session()->pull('authToken') !== $request->input('auth_token')) {
            $request->session()->forget(['authToken', 'deviceCode']);

            throw InvalidAuthTokenException::different();
        }

        return $request->session()->pull('deviceCode')
            ?? throw new Exception('Device code was not present in the session.');
    }
}
