<?php

namespace LaraGram\Citadel\Exceptions;

use LaraGram\Auth\Access\AuthorizationException;
use LaraGram\Support\Arr;

class MissingAbilityException extends AuthorizationException
{
    /**
     * The abilities that the user did not have.
     *
     * @var string[]
     */
    protected array $abilities;

    /**
     * Create a new missing ability exception.
     *
     * @param  string[]|string  $abilities
     */
    public function __construct(array|string $abilities = [], string $message = 'Invalid ability provided.')
    {
        parent::__construct($message);

        $this->abilities = Arr::wrap($abilities);
    }

    /**
     * Get the abilities that the user did not have.
     *
     * @return string[]
     */
    public function abilities(): array
    {
        return $this->abilities;
    }

    /**
     * Get the scopes that the token did not have.
     *
     * @return string[]
     */
    public function scopes(): array
    {
        return $this->abilities;
    }
}
