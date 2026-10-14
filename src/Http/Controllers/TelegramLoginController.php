<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\Telegram\InvalidTelegramDataException;
use LaraGram\Citadel\Telegram\TelegramAuthenticator;
use LaraGram\Contracts\Auth\StatefulGuard;
use LaraGram\Http\BaseResponse as Response;
use LaraGram\Http\Request;
use LaraGram\Validation\ValidationException;

/**
 * Signs users in on the web with the Telegram Login Widget (or a bot "login_url" button),
 * for example before the OAuth authorization screen.
 */
class TelegramLoginController
{
    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected StatefulGuard $guard,
        protected TelegramAuthenticator $authenticator,
    ) {
    }

    /**
     * Show the Login Widget, or sign the user in with the data Telegram redirected back with.
     *
     * @throws \LaraGram\Validation\ValidationException
     */
    public function __invoke(Request $request): mixed
    {
        if (! $request->filled('hash')) {
            return response()->view('citadel::telegram-login', [
                'botUsername' => ltrim((string) (Citadel::botConnection()['username'] ?? ''), '@'),
                'callbackUrl' => route('citadel.telegram.login'),
            ]);
        }

        try {
            $identity = $this->authenticator->verifyLoginWidget($request->query());
        } catch (InvalidTelegramDataException $e) {
            throw ValidationException::withMessages(['telegram' => $e->getMessage()]);
        }

        $user = Citadel::resolveTelegramUser($identity, $this->guard->getProvider());

        if (! $user) {
            throw ValidationException::withMessages(['telegram' => 'This Telegram account is not registered.']);
        }

        $this->guard->login($user, true);

        $request->session()->regenerate();

        return redirect()->intended(config('citadel.telegram.home', '/'));
    }
}
