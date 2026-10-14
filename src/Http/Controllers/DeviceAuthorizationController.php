<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\ClientRepository;
use LaraGram\Citadel\Contracts\DeviceAuthorizationViewResponse;
use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Citadel\Telegram\DeepLink;
use LaraGram\Contracts\Auth\StatefulGuard;
use LaraGram\Http\RedirectResponse;
use LaraGram\Http\Request;
use LaraGram\Support\Str;

class DeviceAuthorizationController
{
    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected StatefulGuard $guard,
        protected AuthorizationServer $server,
        protected ClientRepository $clients,
    ) {
    }

    /**
     * Authorize a device to access the user's account.
     */
    public function __invoke(Request $request, DeviceAuthorizationViewResponse $viewResponse): RedirectResponse|DeviceAuthorizationViewResponse
    {
        if (! $userCode = $request->query('user_code')) {
            return to_route('citadel.device');
        }

        $deviceCode = $this->server->findPendingDeviceCode((string) $userCode);

        if (! $deviceCode) {
            return to_route('citadel.device')
                ->withInput(['user_code' => $userCode])
                ->withErrors([
                    'user_code' => 'Incorrect code.',
                ]);
        }

        $request->session()->put('authToken', $authToken = Str::random());
        $request->session()->put('deviceCode', $deviceCode->getKey());

        return $viewResponse->withParameters([
            'client' => $this->clients->find($deviceCode->client_id),
            'user' => $this->guard->user(),
            'scopes' => Citadel::scopesFor((array) $deviceCode->scopes),
            'request' => $request,
            'authToken' => $authToken,
            'telegramUri' => DeepLink::forDeviceCode($deviceCode),
        ]);
    }
}
