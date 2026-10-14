<?php

namespace LaraGram\Citadel\Console;

use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\Client;
use LaraGram\Citadel\ClientRepository;
use LaraGram\Console\Attribute\AsCommand;
use LaraGram\Console\Command;

#[AsCommand(name: 'citadel:client')]
class ClientCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'citadel:client
            {--password : Create a password grant client}
            {--client : Create a client credentials grant client}
            {--implicit : Create an implicit grant client}
            {--device : Create a device authorization grant client}
            {--telegram : Create a Telegram (Mini App / Login Widget) grant client}
            {--name= : The name of the client}
            {--provider= : The name of the user provider}
            {--redirect_uri= : The URI to redirect to after authorization }
            {--public : Create a public client (without secret) }';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create a client for issuing OAuth access tokens';

    /**
     * Execute the console command.
     */
    public function handle(ClientRepository $clients): void
    {
        if (! $this->option('name')) {
            $this->input->setOption('name', $this->components->ask(
                'What should we name the client?',
                config('app.name')
            ));
        }

        $client = match (true) {
            $this->option('password') => $this->createPasswordClient($clients),
            $this->option('client') => $clients->createClientCredentialsGrantClient($this->option('name')),
            $this->option('implicit') => $this->createImplicitClient($clients),
            $this->option('device') => $this->createDeviceCodeClient($clients),
            $this->option('telegram') => $clients->createTelegramGrantClient($this->option('name'), $this->option('provider') ?: null),
            default => $this->createAuthCodeClient($clients),
        };

        $this->components->info('New client created successfully.');

        $this->components->twoColumnDetail('Client ID', $client->getKey());

        if ($client->confidential()) {
            $this->components->twoColumnDetail('Client Secret', $client->plainSecret);
            $this->components->warn('The client secret will not be shown again, so don\'t lose it!');
        }
    }

    /**
     * Create a new password grant client.
     */
    protected function createPasswordClient(ClientRepository $clients): Client
    {
        $provider = $this->option('provider') ?: $this->components->choice(
            'Which user provider should this client use to retrieve users?',
            collect(config('auth.providers'))->keys()->all(),
            Citadel::defaultProvider()
        );

        $confidential = $this->option('public')
            ? false
            : $this->components->confirm('Would you like to make this client confidential?');

        return $clients->createPasswordGrantClient($this->option('name'), $provider, $confidential);
    }

    /**
     * Create an implicit grant client.
     */
    protected function createImplicitClient(ClientRepository $clients): Client
    {
        $redirect = $this->option('redirect_uri') ?: $this->components->ask(
            'Where should we redirect the request after authorization?',
            url('/auth/callback')
        );

        return $clients->createImplicitGrantClient($this->option('name'), explode(',', $redirect));
    }

    /**
     * Create a device code client.
     */
    protected function createDeviceCodeClient(ClientRepository $clients): Client
    {
        $confidential = $this->option('public')
            ? false
            : $this->components->confirm('Would you like to make this client confidential?', true);

        return $clients->createDeviceAuthorizationGrantClient($this->option('name'), $confidential);
    }

    /**
     * Create an authorization code client.
     */
    protected function createAuthCodeClient(ClientRepository $clients): Client
    {
        $redirect = $this->option('redirect_uri') ?: $this->components->ask(
            'Where should we redirect the request after authorization?',
            url('/auth/callback')
        );

        $confidential = $this->option('public')
            ? false
            : $this->components->confirm('Would you like to make this client confidential?', true);

        $enableDeviceFlow = Citadel::$deviceCodeGrantEnabled &&
            $this->components->confirm('Would you like to enable the device authorization flow for this client?');

        return $clients->createAuthorizationCodeGrantClient(
            $this->option('name'), explode(',', $redirect), $confidential, null, $enableDeviceFlow
        );
    }
}
