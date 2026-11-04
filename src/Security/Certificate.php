<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Security;

use Beziworld\WezelKrajowy\Exceptions\InvalidConfiguration;
use Carbon\CarbonImmutable;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\File\X509;
use Throwable;

/**
 * X.509 certificate with its public key.
 */
final class Certificate
{
    private function __construct(
        private readonly string $der,
        private readonly PublicKey $publicKey,
        private readonly string $subject,
        private readonly ?CarbonImmutable $validTo,
    ) {}

    /**
     * Loads a certificate from a file path, a PEM string or base64 DER.
     *
     * @throws InvalidConfiguration
     */
    public static function load(string $source, string $configKey = 'certificate'): self
    {
        $content = KeyMaterial::read($source, $configKey);

        if (str_contains($content, '-----BEGIN CERTIFICATE-----')) {
            if (preg_match('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $content, $match) !== 1) {
                throw InvalidConfiguration::invalid($configKey, 'the certificate setting', 'malformed PEM certificate');
            }
            $content = $match[1];
        }

        $der = base64_decode((string) preg_replace('/\s+/', '', $content), true);

        if ($der === false || $der === '') {
            $der = $content;
        }

        return self::fromDer($der, $configKey);
    }

    /**
     * @throws InvalidConfiguration
     */
    public static function fromDer(string $der, string $configKey = 'certificate'): self
    {
        try {
            $x509 = new X509();
            $parsed = $x509->loadX509($der);
            $publicKey = $parsed !== false ? $x509->getPublicKey() : null;
        } catch (Throwable) {
            $parsed = false;
            $publicKey = null;
        }

        if ($parsed === false || ! $publicKey instanceof PublicKey) {
            throw InvalidConfiguration::invalid($configKey, 'the certificate setting', 'not a readable X.509 certificate');
        }

        $subject = $x509->getDN(X509::DN_STRING);
        $validTo = $parsed['tbsCertificate']['validity']['notAfter'] ?? null;
        $validToValue = is_array($validTo) ? ($validTo['utcTime'] ?? $validTo['generalTime'] ?? null) : null;

        return new self(
            $der,
            $publicKey,
            is_string($subject) ? $subject : '',
            is_string($validToValue) ? CarbonImmutable::parse($validToValue)->setTimezone('UTC') : null,
        );
    }

    public function der(): string
    {
        return $this->der;
    }

    public function base64(): string
    {
        return base64_encode($this->der);
    }

    public function pem(): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split($this->base64(), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    public function publicKey(): PublicKey
    {
        return $this->publicKey;
    }

    public function isEc(): bool
    {
        return $this->publicKey instanceof EC\PublicKey;
    }

    public function isRsa(): bool
    {
        return $this->publicKey instanceof RSA\PublicKey;
    }

    /**
     * SHA-256 fingerprint as lowercase hex.
     */
    public function fingerprint(): string
    {
        return hash('sha256', $this->der);
    }

    public function subject(): string
    {
        return $this->subject;
    }

    public function validTo(): ?CarbonImmutable
    {
        return $this->validTo;
    }

    /**
     * Verifies a raw XML Signature value over the given data.
     *
     * ECDSA signatures use the XML Signature 1.1 r||s encoding, RSA
     * signatures use PKCS #1 v1.5.
     */
    public function verify(string $data, string $signature, string $keyType, string $hash): bool
    {
        try {
            if ($keyType === 'ec' && $this->publicKey instanceof EC\PublicKey) {
                return $this->publicKey->withSignatureFormat('IEEE')->withHash($hash)->verify($data, $signature);
            }

            if ($keyType === 'rsa' && $this->publicKey instanceof RSA\PublicKey) {
                return $this->publicKey->withPadding(RSA::SIGNATURE_PKCS1)->withHash($hash)->verify($data, $signature);
            }
        } catch (Throwable) {
            return false;
        }

        return false;
    }
}
