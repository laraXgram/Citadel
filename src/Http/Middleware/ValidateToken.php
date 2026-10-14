<?php

namespace LaraGram\Citadel\Http\Middleware;

use Closure;
use LaraGram\Auth\AuthenticationException;
use LaraGram\Citadel\AccessToken;
use LaraGram\Citadel\Contracts\HasAbilities;
use LaraGram\Citadel\OAuth\Jwt;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Citadel\OAuth\ResourceServer;
use LaraGram\Http\Request;
use LaraGram\Http\BaseResponse as Response;

abstract class ValidateToken
{
    /**
     * Specify the abilities (or scopes) for the middleware.
     *
     * @param  string[]|string  $ability
     */
    public static function using(array|string $ability, string ...$abilities): string
    {
        if (is_array($ability)) {
            return static::class.':'.implode(',', $ability);
        }

        return static::class.':'.implode(',', [$ability, ...$abilities]);
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\LaraGram\Http\Request): (\LaraGram\Http\BaseResponse)  $next
     *
     * @throws \LaraGram\Auth\AuthenticationException
     * @throws \LaraGram\Citadel\Exceptions\MissingAbilityException
     */
    public function handle(Request $request, Closure $next, string ...$abilities): Response
    {
        $this->validate($this->validateToken($request), ...$abilities);

        return $next($request);
    }

    /**
     * Get the access token of the request.
     *
     * Users authenticated by a guard bring their token; a token without a user
     * (client credentials) is validated against the resource server directly.
     *
     * @throws \LaraGram\Auth\AuthenticationException
     */
    protected function validateToken(Request $request): HasAbilities
    {
        if ($token = $request->user()?->currentAccessToken()) {
            return $token;
        }

        $bearer = $request->bearerToken();

        if (! $bearer || ! Jwt::looksLikeJwt($bearer)) {
            throw new AuthenticationException;
        }

        try {
            return new AccessToken(app(ResourceServer::class)->validateAccessToken($bearer));
        } catch (OAuthServerException) {
            throw new AuthenticationException;
        }
    }

    /**
     * Validate the token against the given abilities.
     *
     * @throws \LaraGram\Auth\AuthenticationException
     * @throws \LaraGram\Citadel\Exceptions\MissingAbilityException
     */
    abstract protected function validate(HasAbilities $token, string ...$abilities): void;
}
