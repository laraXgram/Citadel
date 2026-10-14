<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\Contracts\DeviceUserCodeViewResponse;
use LaraGram\Http\RedirectResponse;
use LaraGram\Http\Request;

class DeviceUserCodeController
{
    /**
     * Show the form for entering the user code.
     */
    public function __invoke(Request $request, DeviceUserCodeViewResponse $viewResponse): RedirectResponse|DeviceUserCodeViewResponse
    {
        if ($userCode = $request->query('user_code')) {
            return to_route('citadel.device.authorizations.authorize', [
                'user_code' => $userCode,
            ]);
        }

        return $viewResponse->withParameters([
            'request' => $request,
        ]);
    }
}
