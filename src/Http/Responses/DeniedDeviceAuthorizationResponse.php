<?php

namespace LaraGram\Citadel\Http\Responses;

use LaraGram\Citadel\Contracts\DeniedDeviceAuthorizationResponse as DeniedDeviceAuthorizationResponseContract;

class DeniedDeviceAuthorizationResponse implements DeniedDeviceAuthorizationResponseContract
{
    /**
     * Create an HTTP response that represents the object.
     *
     * @param  \LaraGram\Http\Request  $request
     * @return \LaraGram\Http\BaseResponse
     */
    public function toResponse($request)
    {
        return to_route('citadel.device')
            ->with('status', 'authorization-denied');
    }
}
