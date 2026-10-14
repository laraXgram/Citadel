<?php

namespace LaraGram\Citadel\OAuth\Grants;

use DateInterval;
use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\OAuth\BearerTokenResponse;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Citadel\Telegram\InvalidTelegramDataException;
use LaraGram\Citadel\Telegram\TelegramAuthenticator;
use LaraGram\Citadel\Telegram\TelegramIdentity;
use LaraGram\Http\Request;

/**
 * Exchanges a payload signed by Telegram for an access token.
 *
 * "telegram_init_data" takes the raw Mini App init data in "init_data";
 * "telegram_login" takes Login Widget fields (or "login_data" as JSON).
 */
class TelegramGrant extends AbstractGrant
{
    /**
     * The grant type of Mini App init data.
     */
    public const INIT_DATA = 'telegram_init_data';

    /**
     * The grant type of Login Widget data.
     */
    public const LOGIN_WIDGET = 'telegram_login';

    /**
     * Create a new Telegram grant.
     */
    public function __construct(
        protected TelegramAuthenticator $authenticator,
        protected string $type = self::INIT_DATA,
    ) {
        //
    }

    /**
     * Get the grant type identifier.
     */
    public function getIdentifier(): string
    {
        return $this->type;
    }

    /**
     * Respond to an access token request.
     */
    public function respondToAccessTokenRequest(Request $request, DateInterval $accessTokenTTL): BearerTokenResponse
    {
        $client = $this->validateClient($request);

        $scopes = $this->validateScopes($this->stringParameter($request, 'scope', $this->defaultScope));

        $identity = $this->verify($request);

        $user = Citadel::resolveTelegramUser($identity, $this->userProvider($client))
            ?? throw OAuthServerException::invalidGrant('The Telegram user is not registered.');

        return $this->respondWithTokens(
            $accessTokenTTL, $client, $user->getAuthIdentifier(), $this->finalizeScopes($scopes, $client)
        );
    }

    /**
     * Verify the Telegram payload of the request.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    protected function verify(Request $request): TelegramIdentity
    {
        try {
            if ($this->type === self::INIT_DATA) {
                $initData = $this->stringParameter($request, 'init_data');

                if (blank($initData)) {
                    throw OAuthServerException::invalidRequest('init_data');
                }

                return $this->authenticator->verifyInitData($initData);
            }

            $fields = $request->input('login_data');

            if (is_string($fields)) {
                $fields = json_decode($fields, true);
            }

            if (! is_array($fields)) {
                $fields = $request->only(['id', 'first_name', 'last_name', 'username', 'photo_url', 'auth_date', 'hash']);
            }

            return $this->authenticator->verifyLoginWidget($fields);
        } catch (InvalidTelegramDataException $e) {
            throw OAuthServerException::invalidGrant($e->getMessage());
        }
    }
}
