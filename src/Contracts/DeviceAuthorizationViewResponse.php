<?php

namespace LaraGram\Citadel\Contracts;

use LaraGram\Contracts\Support\Responsable;

interface DeviceAuthorizationViewResponse extends Responsable
{
    /**
     * Specify the parameters that should be passed to the view.
     *
     * @param  array<string, mixed>  $parameters
     */
    public function withParameters(array $parameters = []): static;
}
