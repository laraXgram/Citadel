<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\NewAccessToken;
use LaraGram\Contracts\Validation\Factory as ValidationFactory;
use LaraGram\Http\Request;
use LaraGram\Http\Response;

class PersonalAccessTokenController
{
    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected ValidationFactory $validation,
    ) {
    }

    /**
     * Get all of the personal access tokens of the authenticated user.
     */
    public function forUser(Request $request): mixed
    {
        return $request->user()->tokens()
            ->where(fn ($query) => $query->whereNull('expires_at')->orWhere('expires_at', '>', now()))
            ->latest()
            ->get();
    }

    /**
     * Create a new personal access token for the user.
     */
    public function store(Request $request): NewAccessToken
    {
        $this->validation->make($request->all(), [
            'name' => ['required', 'max:255'],
            'abilities' => ['array'],
            'abilities.*' => ['string', 'max:255'],
            'expires_at' => ['nullable', 'date', 'after:now'],
        ])->validate();

        return $request->user()->createToken(
            $request->name,
            $request->abilities ?: ['*'],
            $request->date('expires_at'),
        );
    }

    /**
     * Delete the given personal access token.
     */
    public function destroy(Request $request, string $tokenId): Response
    {
        $deleted = $request->user()->tokens()->whereKey($tokenId)->delete();

        return new Response('', $deleted ? Response::HTTP_NO_CONTENT : 404);
    }
}
