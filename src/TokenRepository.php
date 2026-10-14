<?php

namespace LaraGram\Citadel;

use LaraGram\Contracts\Auth\Authenticatable;
use LaraGram\Database\Eloquent\Collection;
use LaraGram\Support\Facades\Date;

class TokenRepository
{
    /**
     * Get a valid OAuth token instance for the given user and ID.
     */
    public function findForUser(string $id, Authenticatable $user): ?Token
    {
        return $user->oauthTokens()
            ->with('client')
            ->where('revoked', false)
            ->where('expires_at', '>', Date::now())
            ->find($id);
    }

    /**
     * Get the valid OAuth token instances for the given user.
     *
     * @return \LaraGram\Database\Eloquent\Collection<int, \LaraGram\Citadel\Token>
     */
    public function forUser(Authenticatable $user): Collection
    {
        return $user->oauthTokens()
            ->with('client')
            ->where('revoked', false)
            ->where('expires_at', '>', Date::now())
            ->get();
    }

    /**
     * Revoke the given access token together with its refresh token.
     */
    public function revoke(Token $token): void
    {
        $token->revoke();

        $token->refreshToken?->revoke();
    }
}
