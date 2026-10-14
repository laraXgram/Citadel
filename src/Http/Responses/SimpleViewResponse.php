<?php

namespace LaraGram\Citadel\Http\Responses;

use Closure;
use LaraGram\Citadel\Contracts\AuthorizationViewResponse;
use LaraGram\Citadel\Contracts\DeviceAuthorizationViewResponse;
use LaraGram\Citadel\Contracts\DeviceUserCodeViewResponse;
use LaraGram\Contracts\Support\Responsable;

class SimpleViewResponse implements
    AuthorizationViewResponse,
    DeviceAuthorizationViewResponse,
    DeviceUserCodeViewResponse
{
    /**
     * An array of arguments that may be passed to the view response and used in the view.
     *
     * @var array<string, mixed>
     */
    protected array $parameters = [];

    /**
     * Create a new response instance.
     *
     * @param  (\Closure(array<string, mixed>): (\LaraGram\Contracts\Support\Responsable|\LaraGram\Http\BaseResponse))|string  $view
     */
    public function __construct(
        protected Closure|string $view,
    ) {
    }

    /**
     * Add parameters to response.
     *
     * @param  array<string, mixed>  $parameters
     */
    public function withParameters(array $parameters = []): static
    {
        $this->parameters = $parameters;

        return $this;
    }

    /**
     * Create an HTTP response that represents the object.
     *
     * @param  \LaraGram\Http\Request  $request
     * @return \LaraGram\Http\BaseResponse
     */
    public function toResponse($request)
    {
        if (! is_callable($this->view) || is_string($this->view)) {
            return response()->view($this->view, $this->parameters);
        }

        $response = call_user_func($this->view, $this->parameters);

        if ($response instanceof Responsable) {
            return $response->toResponse($request);
        }

        return $response;
    }
}
