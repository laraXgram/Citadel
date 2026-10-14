<?php

namespace LaraGram\Citadel\Http\Controllers;

use Closure;
use LaraGram\Citadel\Exceptions\OAuthServerException;
use LaraGram\Citadel\OAuth\OAuthServerException as OAuthError;

trait HandlesOAuthErrors
{
    /**
     * Perform the given callback with exception handling.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @return TResult
     *
     * @throws \LaraGram\Citadel\Exceptions\OAuthServerException
     */
    protected function withErrorHandling(Closure $callback, bool $useFragment = false)
    {
        try {
            return $callback();
        } catch (OAuthError $e) {
            throw new OAuthServerException($e, $useFragment);
        }
    }
}
