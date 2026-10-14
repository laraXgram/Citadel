<?php

namespace LaraGram\Citadel\Http\Middleware;

use Closure;
use LaraGram\Citadel\ApiTokenCookieFactory;
use LaraGram\Citadel\Citadel;
use LaraGram\Http\BaseResponse;
use LaraGram\Http\JsonResponse;
use LaraGram\Http\Request;
use LaraGram\Http\Response;

/**
 * Attaches the encrypted API token cookie to responses for logged-in users,
 * so first-party JavaScript can call the API without handling tokens.
 */
class CreateFreshApiToken
{
    /**
     * The authentication guard.
     */
    protected ?string $guard = null;

    /**
     * Create a new middleware instance.
     */
    public function __construct(
        protected ApiTokenCookieFactory $cookieFactory,
    ) {
    }

    /**
     * Specify the guard for the middleware.
     */
    public static function using(?string $guard = null): string
    {
        $guard = is_null($guard) ? '' : ':'.$guard;

        return static::class.$guard;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\LaraGram\Http\Request): (\LaraGram\Http\BaseResponse)  $next
     */
    public function handle(Request $request, Closure $next, ?string $guard = null): BaseResponse
    {
        $this->guard = $guard;

        $response = $next($request);

        if ($this->shouldReceiveFreshToken($request, $response)) {
            $response->withCookie($this->cookieFactory->make(
                $request->user($this->guard)->getAuthIdentifier(), $request->session()->token()
            ));
        }

        return $response;
    }

    /**
     * Determine if the given request should receive a fresh token.
     */
    protected function shouldReceiveFreshToken(Request $request, BaseResponse $response): bool
    {
        return $this->requestShouldReceiveFreshToken($request) &&
               $this->responseShouldReceiveFreshToken($response);
    }

    /**
     * Determine if the request should receive a fresh token.
     */
    protected function requestShouldReceiveFreshToken(Request $request): bool
    {
        return $request->isMethod('GET') && $request->user($this->guard);
    }

    /**
     * Determine if the response should receive a fresh token.
     */
    protected function responseShouldReceiveFreshToken(BaseResponse $response): bool
    {
        return ($response instanceof Response ||
                $response instanceof JsonResponse) &&
                ! $this->alreadyContainsToken($response);
    }

    /**
     * Determine if the given response already contains an API token.
     */
    protected function alreadyContainsToken(BaseResponse $response): bool
    {
        foreach ($response->headers->getCookies() as $cookie) {
            if ($cookie->getName() === Citadel::cookie()) {
                return true;
            }
        }

        return false;
    }
}
