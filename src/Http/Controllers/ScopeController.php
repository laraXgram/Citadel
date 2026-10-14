<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\Citadel;
use LaraGram\Support\Collection;

class ScopeController
{
    /**
     * Get all of the available scopes for the application.
     *
     * @return \LaraGram\Support\Collection<int, \LaraGram\Citadel\Scope>
     */
    public function all(): Collection
    {
        return Citadel::scopes();
    }
}
