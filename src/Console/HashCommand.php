<?php

namespace LaraGram\Citadel\Console;

use LaraGram\Citadel\Citadel;
use LaraGram\Console\Attribute\AsCommand;
use LaraGram\Console\Command;
use LaraGram\Support\Facades\Hash;

#[AsCommand(name: 'citadel:hash')]
class HashCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'citadel:hash {--force : Force the operation to run without confirmation prompt}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Hash all of the existing secrets in the clients table';

    /**
     * Execute the console command.
     */
    public function handle(): void
    {
        if ($this->option('force') ||
            $this->components->confirm('Are you sure you want to hash all client secrets? This cannot be undone.')) {
            foreach (Citadel::client()->newQuery()->whereNotNull('secret')->cursor() as $client) {
                $secret = $client->getAttributes()['secret'];

                if (Hash::isHashed($secret) && ! Hash::needsRehash($secret)) {
                    continue;
                }

                $client->timestamps = false;

                $client->forceFill([
                    'secret' => $secret,
                ])->save();
            }

            $this->components->info('All client secrets were successfully hashed.');
        }
    }
}
