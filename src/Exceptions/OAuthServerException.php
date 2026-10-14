<?php

namespace LaraGram\Citadel\Exceptions;

use LaraGram\Citadel\OAuth\OAuthServerException as OAuthError;
use LaraGram\Http\Exceptions\HttpResponseException;

/**
 * Wraps an OAuth error so the exception handler renders its response untouched.
 */
class OAuthServerException extends HttpResponseException
{
    /**
     * Create a new OAuthServerException.
     */
    public function __construct(
        protected OAuthError $error,
        bool $useFragment = false,
    ) {
        parent::__construct($error->toResponse($useFragment), $error);
    }

    /**
     * Get the underlying OAuth error.
     */
    public function error(): OAuthError
    {
        return $this->error;
    }
}
