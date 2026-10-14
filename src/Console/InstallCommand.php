<?php

namespace LaraGram\Citadel\Console;

use LaraGram\Console\Attribute\AsCommand;
use LaraGram\Console\Command;

#[AsCommand(name: 'citadel:install')]
class InstallCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'citadel:install
                            {--oauth : Also generate the OAuth keys}
                            {--force : Overwrite keys they already exist}
                            {--length=4096 : The length of the private key}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Run the commands necessary to prepare Citadel for use';

    /**
     * Execute the console command.
     */
    public function handle(): void
    {
        $this->call('vendor:publish', ['--tag' => 'citadel-config']);
        $this->call('vendor:publish', ['--tag' => 'citadel-migrations']);

        if ($this->option('oauth') || $this->components->confirm('Will this application act as an OAuth2 server (third-party apps, MCP clients, devices)?', false)) {
            $this->call('citadel:keys', [
                '--force' => $this->option('force'),
                '--length' => $this->option('length'),
            ]);
        }

        if ($this->components->confirm('Would you like to run all pending database migrations?', true)) {
            $this->call('migrate');
        }

        $this->components->info('Citadel installed. Add the HasApiTokens trait to your user model and protect routes with the "auth:citadel" middleware.');
    }
}
