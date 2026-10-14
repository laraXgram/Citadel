<?php

namespace LaraGram\Citadel\OAuth;

use InvalidArgumentException;
use UnexpectedValueException;

/**
 * A minimal JSON Web Token (RFC 7519) codec for the RS256 and HS256 algorithms.
 */
class Jwt
{
    /**
     * The number of seconds of clock skew tolerated when checking time claims.
     */
    public static int $leeway = 0;

    /**
     * Encode and sign the given claims.
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, mixed>  $header
     */
    public static function encode(array $claims, CryptKey|string $key, string $algorithm = 'RS256', array $header = []): string
    {
        $segments = [
            static::base64UrlEncode(static::json(['typ' => 'JWT', 'alg' => $algorithm, ...$header])),
            static::base64UrlEncode(static::json($claims)),
        ];

        $segments[] = static::base64UrlEncode(static::sign(implode('.', $segments), $key, $algorithm));

        return implode('.', $segments);
    }

    /**
     * Verify the token signature and its time claims, and return its claims.
     *
     * @param  string[]  $algorithms
     * @return array<string, mixed>
     *
     * @throws \UnexpectedValueException
     */
    public static function decode(string $jwt, CryptKey|string $key, array $algorithms = ['RS256'], bool $verifyTime = true): array
    {
        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments.');
        }

        [$encodedHeader, $encodedClaims, $encodedSignature] = $segments;

        $header = json_decode(static::base64UrlDecode($encodedHeader), true);
        $claims = json_decode(static::base64UrlDecode($encodedClaims), true);
        $signature = static::base64UrlDecode($encodedSignature);

        if (! is_array($header) || ! is_array($claims)) {
            throw new UnexpectedValueException('Malformed token.');
        }

        if (! in_array($header['alg'] ?? null, $algorithms, true)) {
            throw new UnexpectedValueException('Algorithm not allowed.');
        }

        if (! static::verify($encodedHeader.'.'.$encodedClaims, $signature, $key, $header['alg'])) {
            throw new UnexpectedValueException('Signature verification failed.');
        }

        if ($verifyTime) {
            static::verifyTime($claims);
        }

        return $claims;
    }

    /**
     * Determine if the given string has the shape of a JWT.
     */
    public static function looksLikeJwt(string $value): bool
    {
        return (bool) preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $value);
    }

    /**
     * Ensure the token is already valid and not yet expired.
     *
     * @param  array<string, mixed>  $claims
     */
    protected static function verifyTime(array $claims): void
    {
        $now = time();

        if (isset($claims['nbf']) && $claims['nbf'] > $now + static::$leeway) {
            throw new UnexpectedValueException('The token cannot be used yet.');
        }

        if (isset($claims['iat']) && $claims['iat'] > $now + static::$leeway) {
            throw new UnexpectedValueException('The token was issued in the future.');
        }

        if (isset($claims['exp']) && $claims['exp'] <= $now - static::$leeway) {
            throw new UnexpectedValueException('The token has expired.');
        }
    }

    /**
     * Sign the given input.
     */
    protected static function sign(string $input, CryptKey|string $key, string $algorithm): string
    {
        return match ($algorithm) {
            'HS256' => hash_hmac('sha256', $input, static::secret($key), true),
            'RS256' => static::rsaSign($input, $key),
            default => throw new InvalidArgumentException("Unsupported algorithm [{$algorithm}]."),
        };
    }

    /**
     * Verify the given signature.
     */
    protected static function verify(string $input, string $signature, CryptKey|string $key, string $algorithm): bool
    {
        return match ($algorithm) {
            'HS256' => hash_equals(hash_hmac('sha256', $input, static::secret($key), true), $signature),
            'RS256' => $key instanceof CryptKey
                && openssl_verify($input, $signature, $key->publicKey(), OPENSSL_ALGO_SHA256) === 1,
            default => false,
        };
    }

    /**
     * Create an RSA SHA-256 signature.
     */
    protected static function rsaSign(string $input, CryptKey|string $key): string
    {
        if (! $key instanceof CryptKey || ! openssl_sign($input, $signature, $key->privateKey(), OPENSSL_ALGO_SHA256)) {
            throw new InvalidArgumentException('Unable to sign the token with the given key.');
        }

        return $signature;
    }

    /**
     * Get the HMAC secret.
     */
    protected static function secret(CryptKey|string $key): string
    {
        if ($key instanceof CryptKey) {
            throw new InvalidArgumentException('HMAC tokens require a shared secret.');
        }

        return $key;
    }

    /**
     * Encode the value as JSON.
     */
    protected static function json(array $value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    /**
     * Encode the given data with URL-safe Base64 without padding.
     */
    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decode URL-safe Base64 data.
     */
    public static function base64UrlDecode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        if ($decoded === false) {
            throw new UnexpectedValueException('Invalid Base64 encoding.');
        }

        return $decoded;
    }
}
