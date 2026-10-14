<?php

namespace LaraGram\Citadel\Http\Responses;

use LaraGram\Citadel\Contracts\ApprovedDeviceAuthorizationResponse as ApprovedDeviceAuthorizationResponseContract;

class ApprovedDeviceAuthorizationResponse implements ApprovedDeviceAuthorizationResponseContract
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
            ->with('status', 'authorization-approved');
    }
}
