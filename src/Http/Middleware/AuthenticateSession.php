<?php

namespace LaraGram\Citadel\Http\Middleware;

use Closure;
use LaraGram\Auth\AuthenticationException;
use LaraGram\Auth\SessionGuard;
use LaraGram\Contracts\Auth\Factory as AuthFactory;
use LaraGram\Http\BaseResponse as Response;
use LaraGram\Http\Request;
use LaraGram\Support\Arr;
use LaraGram\Support\Collection;

/**
 * Logs SPA sessions out on other devices once the user's password changes.
 */
class AuthenticateSession
{
    /**
     * Create a new middleware instance.
     */
    public function __construct(
        protected AuthFactory $auth,
    ) {
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\LaraGram\Http\Request): (\LaraGram\Http\BaseResponse)  $next
     *
     * @throws \LaraGram\Auth\AuthenticationException
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $request->hasSession() || ! $request->user()) {
            return $next($request);
        }

        $guards = Collection::make(Arr::wrap(config('citadel.guard')))
            ->mapWithKeys(fn ($guard) => [$guard => $this->auth->guard($guard)])
            ->filter(fn ($guard) => $guard instanceof SessionGuard);

        $shouldLogout = $guards->filter(
            fn ($guard, $driver) => $request->session()->has('password_hash_'.$driver)
        )->filter(
            fn ($guard, $driver) => ! $this->validatePasswordHash(
                $guard,
                $request->user()->getAuthPassword(),
                $request->session()->get('password_hash_'.$driver)
            )
        );

        if ($shouldLogout->isNotEmpty()) {
            $shouldLogout->each->logoutCurrentDevice();

            $request->session()->flush();

            throw new AuthenticationException('Unauthenticated.', [...$shouldLogout->keys()->all(), 'citadel']);
        }

        return tap($next($request), function () use ($request, $guards) {
            if (! is_null($guard = $this->getFirstGuardWithUser($guards->keys()))) {
                $this->storePasswordHashInSession($request, $guard);
            }
        });
    }

    /**
     * Get the first authentication guard that has a user.
     */
    protected function getFirstGuardWithUser(Collection $guards): ?string
    {
        return $guards->first(function ($guard) {
            $guardInstance = $this->auth->guard($guard);

            return method_exists($guardInstance, 'hasUser') &&
                   $guardInstance->hasUser();
        });
    }

    /**
     * Store the user's current password hash in the session.
     */
    protected function storePasswordHashInSession(Request $request, string $guard): void
    {
        $guardInstance = $this->auth->guard($guard);

        $request->session()->put([
            "password_hash_{$guard}" => $guardInstance->hashPasswordForCookie($guardInstance->user()->getAuthPassword()),
        ]);
    }

    /**
     * Validate the password hash against the stored value.
     */
    protected function validatePasswordHash(SessionGuard $guard, ?string $passwordHash, string $storedValue): bool
    {
        return hash_equals($guard->hashPasswordForCookie($passwordHash), $storedValue);
    }
}
