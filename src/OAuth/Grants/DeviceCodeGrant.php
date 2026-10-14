<?php

namespace LaraGram\Citadel\OAuth\Grants;

use DateInterval;
use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\DeviceCode;
use LaraGram\Citadel\Events\DeviceAuthorizationCompleted;
use LaraGram\Citadel\Events\DeviceAuthorizationRequested;
use LaraGram\Citadel\OAuth\BearerTokenResponse;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Citadel\Telegram\DeepLink;
use LaraGram\Http\JsonResponse;
use LaraGram\Http\Request;
use LaraGram\Support\Facades\Date;

/**
 * The device authorization grant (RFC 8628), for CLIs, TVs and MCP clients.
 *
 * Besides the verification page, the user may approve the device in the
 * Telegram bot: the response carries a "verification_uri_telegram" deep link.
 */
class DeviceCodeGrant extends AbstractGrant
{
    /**
     * The characters used for user codes (no vowels, no look-alikes).
     */
    protected const USER_CODE_CHARACTERS = 'BCDFGHJKLMNPQRSTVWXZ';

    /**
     * Create a new device code grant.
     */
    public function __construct(
        protected DateInterval $deviceCodeTTL,
        protected string $verificationUri,
        protected int $retryInterval = 5,
    ) {
        //
    }

    /**
     * Get the grant type identifier.
     */
    public function getIdentifier(): string
    {
        return 'urn:ietf:params:oauth:grant-type:device_code';
    }

    /**
     * Determine if the grant can respond to a device authorization request.
     */
    public function canRespondToDeviceAuthorizationRequest(Request $request): bool
    {
        return true;
    }

    /**
     * Respond to a device authorization request.
     */
    public function respondToDeviceAuthorizationRequest(Request $request): JsonResponse
    {
        $client = $this->getClientOrFail($this->stringParameter($request, 'client_id'));

        $scopes = $this->finalizeScopes(
            $this->validateScopes($this->stringParameter($request, 'scope', $this->defaultScope)), $client
        );

        $expiresAt = Date::now()->add($this->deviceCodeTTL);

        $deviceCode = Citadel::deviceCode()->forceFill([
            'id' => $this->generateUniqueIdentifier(),
            'user_id' => null,
            'client_id' => $client->getKey(),
            'user_code' => $this->generateUserCode(),
            'scopes' => $scopes,
            'revoked' => false,
            'user_approved_at' => null,
            'last_polled_at' => null,
            'expires_at' => $expiresAt,
        ]);

        $deviceCode->save();

        $this->events->dispatch(new DeviceAuthorizationRequested($deviceCode));

        $userCode = $deviceCode->formattedUserCode();

        return new JsonResponse(array_filter([
            'device_code' => $this->encrypt([
                'device_code_id' => $deviceCode->getKey(),
                'client_id' => (string) $client->getKey(),
                'expire_time' => $expiresAt->getTimestamp(),
            ]),
            'user_code' => $userCode,
            'verification_uri' => $this->verificationUri,
            'verification_uri_complete' => $this->verificationUri.'?user_code='.$userCode,
            'verification_uri_telegram' => DeepLink::forDeviceCode($deviceCode),
            'expires_in' => $expiresAt->getTimestamp() - time(),
            'interval' => $this->retryInterval,
        ]), 200, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }

    /**
     * Respond to an access token request (the device polling for its tokens).
     */
    public function respondToAccessTokenRequest(Request $request, DateInterval $accessTokenTTL): BearerTokenResponse
    {
        $client = $this->validateClient($request);

        $encrypted = $this->stringParameter($request, 'device_code');

        if (blank($encrypted)) {
            throw OAuthServerException::invalidRequest('device_code');
        }

        $payload = $this->decrypt($encrypted);

        if (! isset($payload['device_code_id'], $payload['client_id'])) {
            throw OAuthServerException::invalidRequest('device_code', 'Cannot decrypt the device code');
        }

        if ((string) $payload['client_id'] !== (string) $client->getKey()) {
            throw OAuthServerException::invalidClient('Device code was not issued to this client');
        }

        $deviceCode = Citadel::deviceCode()->newQuery()->whereKey($payload['device_code_id'])->first();

        if (! $deviceCode || $deviceCode->revoked) {
            throw OAuthServerException::invalidRequest('device_code', 'Device code has been revoked');
        }

        if (time() > (int) ($payload['expire_time'] ?? 0)) {
            throw OAuthServerException::expiredToken();
        }

        $lastPolledAt = $deviceCode->last_polled_at;

        $deviceCode->forceFill(['last_polled_at' => Date::now()])->save();

        if ($lastPolledAt && $lastPolledAt->getTimestamp() + $this->retryInterval > time()) {
            throw OAuthServerException::slowDown();
        }

        if (is_null($deviceCode->user_id)) {
            throw OAuthServerException::authorizationPending();
        }

        if (is_null($deviceCode->user_approved_at)) {
            $deviceCode->forceFill(['revoked' => true])->save();

            throw OAuthServerException::accessDenied('The user denied the request');
        }

        $deviceCode->forceFill(['revoked' => true])->save();

        return $this->respondWithTokens(
            $accessTokenTTL, $client, $deviceCode->user_id, $this->finalizeScopes((array) $deviceCode->scopes, $client)
        );
    }

    /**
     * Record the user's decision for a pending device code.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public function completeDeviceAuthorizationRequest(DeviceCode|string $deviceCode, string|int $userId, bool $approved): DeviceCode
    {
        if (is_string($deviceCode)) {
            $deviceCode = Citadel::deviceCode()->newQuery()->whereKey($deviceCode)->first();
        }

        if (! $deviceCode || ! $deviceCode->pending()) {
            throw OAuthServerException::invalidRequest('user_code', 'The device code is invalid, expired or already used.');
        }

        $deviceCode->forceFill([
            'user_id' => $userId,
            'user_approved_at' => $approved ? Date::now() : null,
        ])->save();

        $this->events->dispatch(new DeviceAuthorizationCompleted($deviceCode, (string) $userId, $approved));

        return $deviceCode;
    }

    /**
     * Find a pending device code by its user code ("ABCD-EFGH" or "ABCDEFGH").
     */
    public function findPendingByUserCode(string $userCode): ?DeviceCode
    {
        $userCode = strtoupper(str_replace(['-', ' '], '', $userCode));

        return Citadel::deviceCode()->newQuery()
            ->where('user_code', $userCode)
            ->whereNull('user_id')
            ->where('expires_at', '>', Date::now())
            ->where('revoked', false)
            ->first();
    }

    /**
     * Generate a new user code.
     */
    protected function generateUserCode(int $length = 8): string
    {
        $characters = static::USER_CODE_CHARACTERS;

        do {
            $code = '';

            for ($i = 0; $i < $length; $i++) {
                $code .= $characters[random_int(0, strlen($characters) - 1)];
            }
        } while (Citadel::deviceCode()->newQuery()->where('user_code', $code)->exists());

        return $code;
    }
}
