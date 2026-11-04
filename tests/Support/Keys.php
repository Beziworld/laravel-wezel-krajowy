<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Tests\Support;

use Beziworld\WezelKrajowy\Security\Certificate;
use Beziworld\WezelKrajowy\Security\KeyPair;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\File\X509;

/**
 * Throwaway keys and self-signed certificates generated at test runtime.
 *
 * No private key is stored in the repository; every test process creates
 * its own material.
 */
final class Keys
{
    /** @var array<string, array{key: string, certificate: string}> */
    private static array $cache = [];

    /**
     * @return array{key: string, certificate: string} PEM private key (PKCS#8) and PEM certificate.
     */
    public static function pem(string $name): array
    {
        return self::$cache[$name] ??= self::generate($name);
    }

    public static function pair(string $name): KeyPair
    {
        $pem = self::pem($name);

        return KeyPair::load($pem['key'], $pem['certificate'], null, $name);
    }

    public static function certificate(string $name): Certificate
    {
        return Certificate::load(self::pem($name)['certificate']);
    }

    /**
     * @return array{key: string, certificate: string}
     */
    private static function generate(string $name): array
    {
        $key = str_starts_with($name, 'rsa')
            ? RSA::createKey(2048)->withPadding(RSA::ENCRYPTION_PKCS1 | RSA::SIGNATURE_PKCS1)
            : EC::createKey('nistp256');

        return ['key' => $key->toString('PKCS8'), 'certificate' => self::selfSigned($key, $name)];
    }

    private static function selfSigned(PrivateKey $key, string $name): string
    {
        $subject = new X509();
        $subject->setDNProp('id-at-organizationName', 'Beziworld Test');
        $subject->setDNProp('id-at-commonName', $name);
        $subject->setPublicKey($key->getPublicKey());

        $issuer = new X509();
        $issuer->setPrivateKey($key);
        $issuer->setDN($subject->getDN());

        $signer = new X509();
        $signer->setStartDate('-1 day');
        $signer->setEndDate('+1 year');
        $signer->setSerialNumber(bin2hex(random_bytes(8)), 16);

        $certificate = $signer->sign($issuer, $subject);

        return $signer->saveX509($certificate);
    }
}
