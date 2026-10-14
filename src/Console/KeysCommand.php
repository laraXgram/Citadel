<?php

namespace LaraGram\Citadel\Console;

use LaraGram\Citadel\Citadel;
use LaraGram\Console\Attribute\AsCommand;
use LaraGram\Console\Command;

#[AsCommand(name: 'citadel:keys')]
class KeysCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'citadel:keys
                                      {--force : Overwrite keys they already exist}
                                      {--length=4096 : The length of the private key}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create the RSA keys that sign OAuth access tokens';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        [$publicKey, $privateKey] = [
            Citadel::keyPath('oauth-public.key'),
            Citadel::keyPath('oauth-private.key'),
        ];

        if ((file_exists($publicKey) || file_exists($privateKey)) && ! $this->option('force')) {
            $this->components->error('Encryption keys already exist. Use the --force option to overwrite them.');

            return Command::FAILURE;
        }

        $key = openssl_pkey_new([
            'private_key_bits' => (int) $this->option('length'),
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false || ! openssl_pkey_export($key, $private)) {
            $this->components->error('Unable to generate the keys: '.openssl_error_string());

            return Command::FAILURE;
        }

        file_put_contents($publicKey, openssl_pkey_get_details($key)['key']);
        file_put_contents($privateKey, $private);

        if (PHP_OS_FAMILY !== 'Windows') {
            chmod($publicKey, 0660);
            chmod($privateKey, 0600);
        }

        $this->components->info('Encryption keys generated successfully.');

        return Command::SUCCESS;
    }
}
