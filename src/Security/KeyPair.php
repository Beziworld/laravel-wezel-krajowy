<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Security;

use Beziworld\WezelKrajowy\Exceptions\InvalidConfiguration;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use Throwable;

/**
 * Private key (ECDSA P-256 or RSA) with the matching certificate.
 */
final class KeyPair
{
    public function __construct(
        private readonly PrivateKey $privateKey,
        private readonly ?Certificate $certificate = null,
    ) {
        if (! $privateKey instanceof EC\PrivateKey && ! $privateKey instanceof RSA\PrivateKey) {
            throw InvalidConfiguration::invalid('key', 'the key setting', 'only EC and RSA private keys are supported');
        }
    }

    /**
     * @throws InvalidConfiguration
     */
    public static function load(string $key, ?string $certificate, ?string $passphrase, string $configKey): self
    {
        $material = KeyMaterial::read($key, $configKey . '.key');

        try {
            $loaded = $passphrase !== null && $passphrase !== ''
                ? PublicKeyLoader::loadPrivateKey($material, $passphrase)
                : PublicKeyLoader::loadPrivateKey($material);
        } catch (Throwable) {
            throw InvalidConfiguration::invalid($configKey . '.key', 'the key setting', 'not a readable private key or wrong passphrase');
        }

        $cert = $certificate !== null && trim($certificate) !== '' ? Certificate::load($certificate, $configKey . '.certificate') : null;

        return new self($loaded, $cert);
    }

    public function privateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    public function certificate(): ?Certificate
    {
        return $this->certificate;
    }

    public function isEc(): bool
    {
        return $this->privateKey instanceof EC\PrivateKey;
    }

    /**
     * XML Signature method used when signing with this key.
     */
    public function signatureMethod(): string
    {
        return $this->isEc() ? Algorithm::ECDSA_SHA256 : Algorithm::RSA_SHA256;
    }

    /**
     * Produces a raw XML Signature value (r||s for ECDSA, PKCS #1 v1.5 for RSA).
     */
    public function sign(string $data): string
    {
        $key = $this->privateKey;

        if ($key instanceof EC\PrivateKey) {
            $signature = $key->withSignatureFormat('IEEE')->withHash('sha256')->sign($data);
        } elseif ($key instanceof RSA\PrivateKey) {
            $signature = $key->withPadding(RSA::SIGNATURE_PKCS1)->withHash('sha256')->sign($data);
        } else {
            $signature = '';
        }

        return is_string($signature) ? $signature : '';
    }

    /**
     * Elliptic curve name in phpseclib notation, null for RSA keys.
     */
    public function curve(): ?string
    {
        $curve = $this->privateKey instanceof EC\PrivateKey ? $this->privateKey->getCurve() : null;

        return is_string($curve) ? $curve : null;
    }
}
