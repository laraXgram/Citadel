<?php

namespace LaraGram\Citadel\Http\Middleware;

use LaraGram\Citadel\Citadel;
use LaraGram\Routing\Pipeline;
use LaraGram\Support\Collection;
use LaraGram\Support\Str;

/**
 * Starts the session (with cookies and CSRF protection) for requests coming
 * from the first-party SPA domains listed in "citadel.stateful".
 */
class EnsureFrontendRequestsAreStateful
{
    /**
     * Handle the incoming requests.
     *
     * @param  \LaraGram\Http\Request  $request
     * @param  callable  $next
     * @return \LaraGram\Http\BaseResponse
     */
    public function handle($request, $next)
    {
        $this->configureSecureCookieSessions();

        return (new Pipeline(app()))->send($request)->through(
            static::fromFrontend($request) ? $this->frontendMiddleware() : []
        )->then(function ($request) use ($next) {
            return $next($request);
        });
    }

    /**
     * Configure secure cookie sessions.
     */
    protected function configureSecureCookieSessions(): void
    {
        config([
            'session.http_only' => true,
            'session.same_site' => 'lax',
        ]);
    }

    /**
     * Get the middleware that should be applied to requests from the "frontend".
     *
     * @return array<int, mixed>
     */
    protected function frontendMiddleware(): array
    {
        $middleware = array_values(array_filter(array_unique([
            config('citadel.middleware.encrypt_cookies', \LaraGram\Cookie\Middleware\EncryptCookies::class),
            \LaraGram\Cookie\Middleware\AddQueuedCookiesToResponse::class,
            \LaraGram\Session\Middleware\StartSession::class,
            config('citadel.middleware.validate_csrf_token', \LaraGram\Foundation\Http\Middleware\PreventRequestForgery::class),
            config('citadel.middleware.authenticate_session'),
        ])));

        array_unshift($middleware, function ($request, $next) {
            $request->attributes->set('citadel', true);

            return $next($request);
        });

        return $middleware;
    }

    /**
     * Determine if the given request is from the first-party application frontend.
     *
     * @param  \LaraGram\Http\Request  $request
     */
    public static function fromFrontend($request): bool
    {
        $domain = $request->headers->get('referer') ?: $request->headers->get('origin');

        if (is_null($domain)) {
            return false;
        }

        $domain = Str::replaceFirst('https://', '', $domain);
        $domain = Str::replaceFirst('http://', '', $domain);
        $domain = Str::endsWith($domain, '/') ? $domain : "{$domain}/";

        $stateful = array_filter(config('citadel.stateful', []));

        return Str::is(Collection::make($stateful)->map(function ($uri) use ($request) {
            $uri = $uri === Citadel::$currentRequestHostPlaceholder ? $request->getHttpHost() : $uri;

            return trim($uri).'/*';
        })->all(), $domain);
    }
}
