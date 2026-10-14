<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\Token;
use LaraGram\Citadel\TokenRepository;
use LaraGram\Database\Eloquent\Collection;
use LaraGram\Http\Request;
use LaraGram\Http\Response;

class AuthorizedAccessTokenController
{
    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected TokenRepository $tokenRepository,
    ) {
    }

    /**
     * Get all of the OAuth tokens the user granted to third-party clients.
     *
     * @return \LaraGram\Database\Eloquent\Collection<int, \LaraGram\Citadel\Token>
     */
    public function forUser(Request $request): Collection
    {
        return $this->tokenRepository->forUser($request->user())
            ->reject(fn (Token $token): bool => $token->client->revoked || $token->client->firstParty())
            ->values();
    }

    /**
     * Revoke the given OAuth token.
     */
    public function destroy(Request $request, string $tokenId): Response
    {
        $token = $this->tokenRepository->findForUser($tokenId, $request->user());

        if (is_null($token)) {
            return new Response('', 404);
        }

        $this->tokenRepository->revoke($token);

        return new Response('', Response::HTTP_NO_CONTENT);
    }
}
