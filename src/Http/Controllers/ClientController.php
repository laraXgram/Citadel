<?php

namespace LaraGram\Citadel\Http\Controllers;

use LaraGram\Citadel\Client;
use LaraGram\Citadel\ClientRepository;
use LaraGram\Citadel\Http\Rules\RedirectRule;
use LaraGram\Contracts\Validation\Factory as ValidationFactory;
use LaraGram\Database\Eloquent\Collection;
use LaraGram\Http\Request;
use LaraGram\Http\Response;

class ClientController
{
    /**
     * Create a client controller instance.
     */
    public function __construct(
        protected ClientRepository $clients,
        protected ValidationFactory $validation,
    ) {
    }

    /**
     * Get all of the clients for the authenticated user.
     *
     * @return \LaraGram\Database\Eloquent\Collection<int, \LaraGram\Citadel\Client>
     */
    public function forUser(Request $request): Collection
    {
        return $this->clients->forUser($request->user());
    }

    /**
     * Store a new client.
     */
    public function store(Request $request): Client
    {
        $this->validation->make($request->all(), [
            'name' => ['required', 'string', 'max:255'],
            'redirect' => ['required', new RedirectRule],
            'confidential' => 'boolean',
        ])->validate();

        $client = $this->clients->createAuthorizationCodeGrantClient(
            $request->name,
            array_map(trim(...), explode(',', $request->redirect)),
            $confidential = (bool) $request->input('confidential', true),
            $request->user(),
        );

        return $confidential ? $client->append(['plain_secret']) : $client;
    }

    /**
     * Update the given client.
     */
    public function update(Request $request, string|int $clientId): Response|Client
    {
        $client = $this->clients->findForUser($clientId, $request->user());

        if (! $client) {
            return new Response('', 404);
        }

        $this->validation->make($request->all(), [
            'name' => ['required', 'string', 'max:255'],
            'redirect' => ['required', new RedirectRule],
        ])->validate();

        $this->clients->update(
            $client, $request->name, array_map(trim(...), explode(',', $request->redirect))
        );

        return $client;
    }

    /**
     * Delete the given client.
     */
    public function destroy(Request $request, string|int $clientId): Response
    {
        $client = $this->clients->findForUser($clientId, $request->user());

        if (! $client) {
            return new Response('', 404);
        }

        $this->clients->delete($client);

        return new Response('', Response::HTTP_NO_CONTENT);
    }
}
