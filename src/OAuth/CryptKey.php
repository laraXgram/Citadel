<?php

namespace LaraGram\Citadel\OAuth;

use LogicException;
use OpenSSLAsymmetricKey;

/**
 * An RSA key loaded from a file ("file://...") or given as PEM contents.
 */
class CryptKey
{
    /**
     * The loaded OpenSSL key.
     */
    protected ?OpenSSLAsymmetricKey $key = null;

    /**
     * The loaded OpenSSL public key.
     */
    protected ?OpenSSLAsymmetricKey $publicKey = null;

    /**
     * Create a new key instance.
     */
    public function __construct(
        protected string $keyPath,
        protected ?string $passPhrase = null,
        protected bool $keyPermissionsCheck = true,
    ) {
        //
    }

    /**
     * Get the key as a private key.
     */
    public function privateKey(): OpenSSLAsymmetricKey
    {
        return $this->key ??= openssl_pkey_get_private($this->contents(), $this->passPhrase ?? '')
            ?: throw new LogicException('Unable to read the OAuth private key: '.openssl_error_string());
    }

    /**
     * Get the key as a public key (derived from the private key when needed).
     */
    public function publicKey(): OpenSSLAsymmetricKey
    {
        return $this->publicKey ??= $this->loadPublicKey();
    }

    /**
     * Load the public key.
     */
    protected function loadPublicKey(): OpenSSLAsymmetricKey
    {
        $contents = $this->contents();

        if (str_contains($contents, 'PRIVATE KEY')) {
            $contents = openssl_pkey_get_details($this->privateKey())['key'];
        }

        return openssl_pkey_get_public($contents)
            ?: throw new LogicException('Unable to read the OAuth public key: '.openssl_error_string());
    }

    /**
     * Get the public key in PEM format.
     */
    public function publicKeyPem(): string
    {
        return openssl_pkey_get_details($this->publicKey())['key'];
    }

    /**
     * Read the key material.
     */
    protected function contents(): string
    {
        if (! str_starts_with($this->keyPath, 'file://')) {
            return $this->keyPath;
        }

        $path = substr($this->keyPath, 7);

        if (! is_readable($path)) {
            throw new LogicException(sprintf('Key path "%s" does not exist or is not readable. Run "php laragram citadel:keys" to create it.', $path));
        }

        if ($this->keyPermissionsCheck && PHP_OS_FAMILY !== 'Windows') {
            $mode = decoct(fileperms($path) & 0777);

            if (! in_array($mode, ['400', '440', '600', '640', '660'], true)) {
                trigger_error(sprintf('Key file "%s" permissions are not correct, recommend changing to 600 or 660 instead of %s', $path, $mode), E_USER_NOTICE);
            }
        }

        return (string) file_get_contents($path);
    }
}
