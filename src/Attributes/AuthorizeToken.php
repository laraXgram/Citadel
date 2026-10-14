<?php

namespace LaraGram\Citadel\Attributes;

use Attribute;
use LaraGram\Citadel\Http\Middleware\CheckAbilities;
use LaraGram\Citadel\Http\Middleware\CheckForAnyAbility;
use LaraGram\Routing\Attributes\Controllers\Middleware;

/**
 * Requires the given token abilities (or scopes) on a controller or action.
 *
 *     #[AuthorizeToken(['orders:read', 'orders:write'])]
 *     #[AuthorizeToken(['orders:read', 'admin'], anyAbility: true)]
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
class AuthorizeToken extends Middleware
{
    /**
     * Create a new attribute instance.
     *
     * @param  string[]|string  $abilities
     * @param  string[]|null  $only
     * @param  string[]|null  $except
     */
    public function __construct(
        array|string $abilities,
        bool $anyAbility = false,
        ?array $only = null,
        ?array $except = null,
    ) {
        parent::__construct(
            $anyAbility ? CheckForAnyAbility::using($abilities) : CheckAbilities::using($abilities),
            $only, $except,
        );
    }
}
