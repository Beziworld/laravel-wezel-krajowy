<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Tests\Support;

use Beziworld\WezelKrajowy\Security\AesKeyWrap;
use Beziworld\WezelKrajowy\Security\Algorithm;
use Beziworld\WezelKrajowy\Security\Certificate;
use Beziworld\WezelKrajowy\Security\ConcatKdf;
use Beziworld\WezelKrajowy\Security\Xml;
use phpseclib3\Crypt\DH;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

/**
 * Encrypts assertions the way login.gov.pl does, for tests only.
 */
final class Encrypter
{
    /**
     * ECDH-ES + ConcatKDF + kw-aes256 + AES-GCM EncryptedAssertion.
     */
    public static function ecdhEs(string $assertionXml, Certificate $recipient, string $partyU = 'login.gov.pl', string $partyV = 'https://sp.example.pl', int $contentKeyLength = 32, string $contentAlgorithm = Algorithm::AES256_GCM): string
    {
        $publicKey = $recipient->publicKey();

        if (! $publicKey instanceof EC\PublicKey) {
            throw new \RuntimeException('EC recipient certificate required.');
        }

        $ephemeral = EC::createKey('nistp256');
        $shared = DH::computeSecret($ephemeral, $publicKey->getEncodedCoordinates());
        $algorithmId = ConcatKdf::encodeParameter(Algorithm::KW_AES256);
        $partyUInfo = ConcatKdf::encodeParameter($partyU);
        $partyVInfo = ConcatKdf::encodeParameter($partyV);
        $kek = ConcatKdf::derive($shared, (string) hex2bin($algorithmId . $partyUInfo . $partyVInfo), 32);

        $contentKey = random_bytes($contentKeyLength);
        $wrapped = AesKeyWrap::wrap($kek, $contentKey);
        $ephemeralPublic = $ephemeral->getPublicKey();
        $point = $ephemeralPublic instanceof EC\PublicKey ? $ephemeralPublic->getEncodedCoordinates() : '';

        return sprintf(
            '<saml2:EncryptedAssertion xmlns:saml2="%s"><xenc:EncryptedData xmlns:xenc="%s" xmlns:ds="%s" xmlns:xenc11="%s" xmlns:dsig11="%s" Id="_enc" Type="http://www.w3.org/2001/04/xmlenc#Element">'
            . '<xenc:EncryptionMethod Algorithm="%s"><ds:DigestMethod Algorithm="%s"/></xenc:EncryptionMethod>'
            . '<ds:KeyInfo><xenc:EncryptedKey Id="_key"><xenc:EncryptionMethod Algorithm="%s"/><ds:KeyInfo>'
            . '<xenc:AgreementMethod Algorithm="%s"><xenc11:KeyDerivationMethod Algorithm="%s">'
            . '<xenc11:ConcatKDFParams AlgorithmID="%s" PartyUInfo="%s" PartyVInfo="%s"><ds:DigestMethod Algorithm="%s"/></xenc11:ConcatKDFParams>'
            . '</xenc11:KeyDerivationMethod><xenc:OriginatorKeyInfo><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>'
            . '<dsig11:PublicKey>%s</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue></xenc:OriginatorKeyInfo></xenc:AgreementMethod>'
            . '</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>'
            . '<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml2:EncryptedAssertion>',
            Xml::SAML,
            Xml::XENC,
            Xml::DS,
            Xml::XENC11,
            Xml::DSIG11,
            $contentAlgorithm,
            Algorithm::SHA256,
            Algorithm::KW_AES256,
            Algorithm::ECDH_ES,
            Algorithm::CONCAT_KDF,
            $algorithmId,
            $partyUInfo,
            $partyVInfo,
            Algorithm::SHA256,
            base64_encode($point),
            base64_encode($wrapped),
            base64_encode(self::gcm($assertionXml, $contentKey)),
        );
    }

    /**
     * RSA-OAEP (MGF1 SHA-1) key transport + AES-256-GCM EncryptedAssertion.
     */
    public static function rsaOaep(string $assertionXml, Certificate $recipient): string
    {
        $publicKey = $recipient->publicKey();

        if (! $publicKey instanceof RSA\PublicKey) {
            throw new \RuntimeException('RSA recipient certificate required.');
        }

        $contentKey = random_bytes(32);
        $encryptedKey = $publicKey->withPadding(RSA::ENCRYPTION_OAEP)->withHash('sha1')->withMGFHash('sha1')->encrypt($contentKey);

        return sprintf(
            '<saml2:EncryptedAssertion xmlns:saml2="%s"><xenc:EncryptedData xmlns:xenc="%s" xmlns:ds="%s" Type="http://www.w3.org/2001/04/xmlenc#Element">'
            . '<xenc:EncryptionMethod Algorithm="%s"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="%s"><ds:DigestMethod Algorithm="%s"/></xenc:EncryptionMethod>'
            . '<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>'
            . '<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml2:EncryptedAssertion>',
            Xml::SAML,
            Xml::XENC,
            Xml::DS,
            Algorithm::AES256_GCM,
            Algorithm::RSA_OAEP_MGF1P,
            Algorithm::SHA1,
            base64_encode((string) $encryptedKey),
            base64_encode(self::gcm($assertionXml, $contentKey)),
        );
    }

    public static function gcm(string $plain, string $key): string
    {
        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($plain, 'aes-' . (strlen($key) * 8) . '-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);

        return $iv . $cipher . $tag;
    }
}
