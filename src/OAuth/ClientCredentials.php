<?php

namespace LaraGram\Citadel\OAuth;

use LaraGram\Citadel\Client;
use LaraGram\Citadel\ClientRepository;
use LaraGram\Http\Request;

/**
 * Reads and checks the client credentials of a request (RFC 6749 section 2.3.1).
 */
class ClientCredentials
{
    /**
     * Get the client ID and secret from the HTTP Basic header or the request body.
     *
     * @return array{0: string|null, 1: string|null}
     */
    public static function fromRequest(Request $request): array
    {
        $header = (string) $request->header('Authorization', '');

        if (str_starts_with(strtolower($header), 'basic ')) {
            $decoded = base64_decode(substr($header, 6), true);

            if ($decoded !== false && str_contains($decoded, ':')) {
                [$id, $secret] = explode(':', $decoded, 2);

                return [rawurldecode($id), rawurldecode($secret)];
            }
        }

        $id = $request->input('client_id');
        $secret = $request->input('client_secret');

        return [
            is_scalar($id) ? (string) $id : null,
            is_scalar($secret) ? (string) $secret : null,
        ];
    }

    /**
     * Authenticate the client of the request: confidential clients must present their secret.
     *
     * @throws \LaraGram\Citadel\OAuth\OAuthServerException
     */
    public static function authenticate(Request $request, ClientRepository $clients): Client
    {
        [$clientId, $clientSecret] = static::fromRequest($request);

        if (blank($clientId)) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        $client = $clients->findActive($clientId) ?? throw OAuthServerException::invalidClient();

        if ($client->confidential() && ! $clients->validateSecret($client, $clientSecret)) {
            throw OAuthServerException::invalidClient();
        }

        return $client;
    }
}
