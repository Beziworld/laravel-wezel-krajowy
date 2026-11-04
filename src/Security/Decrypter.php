<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Security;

use Beziworld\WezelKrajowy\Exceptions\DecryptionFailed;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use DOMElement;
use phpseclib3\Crypt\DH;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use Throwable;

/**
 * XML Encryption 1.1 decryption of saml2:EncryptedAssertion.
 *
 * Supports the login.gov.pl profile (ECDH-ES key agreement, ConcatKDF,
 * AES key wrap, AES-GCM content encryption) and RSA-OAEP key transport for
 * service providers registered with RSA encryption certificates.
 */
final class Decrypter
{
    /**
     * Named curve OIDs mapped to phpseclib curve names.
     *
     * @var array<string, string>
     */
    private const array CURVES = [
        '1.2.840.10045.3.1.7' => 'secp256r1',
        '1.3.132.0.34' => 'secp384r1',
        '1.3.132.0.35' => 'secp521r1',
    ];

    private const int GCM_IV_LENGTH = 12;

    private const int GCM_TAG_LENGTH = 16;

    /**
     * Decrypts an EncryptedAssertion and returns the saml2:Assertion element.
     *
     * @throws DecryptionFailed
     */
    public static function decryptAssertion(DOMElement $encryptedAssertion, KeyPair $key): DOMElement
    {
        try {
            $encryptedData = Xml::single($encryptedAssertion, Xml::XENC, 'EncryptedData');
        } catch (InvalidResponse) {
            throw DecryptionFailed::because('EncryptedAssertion must contain exactly one EncryptedData');
        }

        $method = self::algorithm($encryptedData);

        if (! isset(Algorithm::GCM_METHODS[$method])) {
            throw DecryptionFailed::because('unsupported content encryption algorithm ' . ($method === '' ? '(none)' : $method));
        }

        $keyInfo = Xml::child($encryptedData, Xml::DS, 'KeyInfo');
        $encryptedKey = ($keyInfo !== null ? Xml::child($keyInfo, Xml::XENC, 'EncryptedKey') : null)
            ?? Xml::child($encryptedAssertion, Xml::XENC, 'EncryptedKey');

        if ($encryptedKey === null) {
            throw DecryptionFailed::because('no EncryptedKey was found');
        }

        $contentKey = self::contentKey($encryptedKey, $key);

        if (! in_array(strlen($contentKey), [16, 24, 32], true)) {
            throw DecryptionFailed::because('the content encryption key has an invalid length');
        }

        $payload = self::cipherValue($encryptedData);

        if (strlen($payload) <= self::GCM_IV_LENGTH + self::GCM_TAG_LENGTH) {
            throw DecryptionFailed::because('the cipher text is too short');
        }

        $plain = openssl_decrypt(
            substr($payload, self::GCM_IV_LENGTH, -self::GCM_TAG_LENGTH),
            'aes-' . (strlen($contentKey) * 8) . '-gcm',
            $contentKey,
            OPENSSL_RAW_DATA,
            substr($payload, 0, self::GCM_IV_LENGTH),
            substr($payload, -self::GCM_TAG_LENGTH),
        );

        if ($plain === false) {
            throw DecryptionFailed::because('the authentication tag does not match');
        }

        return self::parseAssertion($plain);
    }

    /**
     * Recovers the content encryption key from an EncryptedKey element.
     *
     * @throws DecryptionFailed
     */
    public static function contentKey(DOMElement $encryptedKey, KeyPair $key): string
    {
        $method = self::algorithm($encryptedKey);
        $cipher = self::cipherValue($encryptedKey);

        if (isset(Algorithm::KEY_WRAP_METHODS[$method])) {
            $kek = self::agreedKey($encryptedKey, $key, Algorithm::KEY_WRAP_METHODS[$method]);
            $unwrapped = AesKeyWrap::unwrap($kek, $cipher);

            if ($unwrapped === null) {
                throw DecryptionFailed::because('the key unwrap integrity check failed, the assertion was encrypted for another key');
            }

            return $unwrapped;
        }

        if ($method === Algorithm::RSA_OAEP_MGF1P || $method === Algorithm::RSA_OAEP) {
            return self::oaep($encryptedKey, $key, $method, $cipher);
        }

        throw DecryptionFailed::because('unsupported key encryption algorithm ' . ($method === '' ? '(none)' : $method));
    }

    /**
     * Performs ECDH-ES and ConcatKDF to obtain the key encryption key.
     */
    private static function agreedKey(DOMElement $encryptedKey, KeyPair $key, int $length): string
    {
        $privateKey = $key->privateKey();

        if (! $privateKey instanceof EC\PrivateKey) {
            throw DecryptionFailed::because('ECDH-ES requires an EC encryption key');
        }

        $keyInfo = Xml::child($encryptedKey, Xml::DS, 'KeyInfo');
        $agreement = $keyInfo !== null ? Xml::child($keyInfo, Xml::XENC, 'AgreementMethod') : null;

        if ($agreement === null || $agreement->getAttribute('Algorithm') !== Algorithm::ECDH_ES) {
            throw DecryptionFailed::because('AgreementMethod with ECDH-ES is required for AES key wrap');
        }

        $derivation = Xml::child($agreement, Xml::XENC11, 'KeyDerivationMethod');
        $parameters = $derivation !== null ? Xml::child($derivation, Xml::XENC11, 'ConcatKDFParams') : null;

        if ($derivation === null || $derivation->getAttribute('Algorithm') !== Algorithm::CONCAT_KDF || $parameters === null) {
            throw DecryptionFailed::because('KeyDerivationMethod must be ConcatKDF with ConcatKDFParams');
        }

        $digest = Xml::child($parameters, Xml::DS, 'DigestMethod');
        $hash = $digest !== null ? (Algorithm::DIGEST_METHODS[$digest->getAttribute('Algorithm')] ?? null) : 'sha256';

        if ($hash === null) {
            throw DecryptionFailed::because('unsupported ConcatKDF digest method');
        }

        $otherInfo = '';

        foreach (['AlgorithmID', 'PartyUInfo', 'PartyVInfo', 'SuppPubInfo', 'SuppPrivInfo'] as $attribute) {
            $decoded = ConcatKdf::decodeParameter($parameters->getAttribute($attribute));

            if ($decoded === null) {
                throw DecryptionFailed::because(sprintf('ConcatKDFParams %s is not valid hex', $attribute));
            }

            $otherInfo .= $decoded;
        }

        $originator = Xml::child($agreement, Xml::XENC, 'OriginatorKeyInfo');
        $keyValue = $originator !== null ? Xml::child($originator, Xml::DS, 'KeyValue') : null;
        $ecKeyValue = $keyValue !== null ? Xml::child($keyValue, Xml::DSIG11, 'ECKeyValue') : null;
        $namedCurve = $ecKeyValue !== null ? Xml::child($ecKeyValue, Xml::DSIG11, 'NamedCurve') : null;
        $publicKey = $ecKeyValue !== null ? Xml::text(Xml::child($ecKeyValue, Xml::DSIG11, 'PublicKey')) : null;

        if ($namedCurve === null || $publicKey === null) {
            throw DecryptionFailed::because('the originator ECKeyValue is missing');
        }

        $curve = self::CURVES[preg_replace('/^urn:oid:/', '', trim($namedCurve->getAttribute('URI'))) ?? ''] ?? null;

        if ($curve === null || strcasecmp($curve, (string) $key->curve()) !== 0) {
            throw DecryptionFailed::because('the originator key curve does not match the encryption key curve');
        }

        $point = base64_decode((string) preg_replace('/\s+/', '', $publicKey), true);

        if ($point === false || $point === '' || $point[0] !== "\x04") {
            throw DecryptionFailed::because('the originator public key is not an uncompressed EC point');
        }

        try {
            $shared = DH::computeSecret($privateKey, $point);
        } catch (Throwable) {
            throw DecryptionFailed::because('the originator public key is not a valid point on the curve');
        }

        $fieldLength = intdiv(strlen($point) - 1, 2);
        $shared = str_pad($shared, $fieldLength, "\0", STR_PAD_LEFT);

        return ConcatKdf::derive($shared, $otherInfo, $length, $hash);
    }

    private static function oaep(DOMElement $encryptedKey, KeyPair $key, string $method, string $cipher): string
    {
        $privateKey = $key->privateKey();

        if (! $privateKey instanceof RSA\PrivateKey) {
            throw DecryptionFailed::because('RSA-OAEP requires an RSA encryption key');
        }

        $encryptionMethod = Xml::child($encryptedKey, Xml::XENC, 'EncryptionMethod');
        $digest = $encryptionMethod !== null ? Xml::child($encryptionMethod, Xml::DS, 'DigestMethod') : null;
        $mgf = $encryptionMethod !== null ? Xml::child($encryptionMethod, Xml::XENC11, 'MGF') : null;
        $label = $encryptionMethod !== null ? Xml::text(Xml::child($encryptionMethod, Xml::XENC, 'OAEPparams')) : null;

        $hash = $digest !== null ? Algorithm::oaepHash($digest->getAttribute('Algorithm')) : 'sha1';
        $mgfHash = $method === Algorithm::RSA_OAEP && $mgf !== null ? Algorithm::oaepHash($mgf->getAttribute('Algorithm')) : 'sha1';

        if ($hash === null || $mgfHash === null) {
            throw DecryptionFailed::because('unsupported RSA-OAEP digest or mask generation function');
        }

        try {
            $result = $privateKey
                ->withPadding(RSA::ENCRYPTION_OAEP)
                ->withHash($hash)
                ->withMGFHash($mgfHash)
                ->withLabel($label !== null ? (string) base64_decode($label, true) : '')
                ->decrypt($cipher);
        } catch (Throwable) {
            $result = false;
        }

        if (! is_string($result) || $result === '') {
            throw DecryptionFailed::because('RSA-OAEP decryption failed, the assertion was encrypted for another key');
        }

        return $result;
    }

    /**
     * Parses the decrypted assertion. Fragments that rely on namespace
     * declarations of the enclosing message are parsed inside a wrapper that
     * declares the SAML namespaces.
     */
    private static function parseAssertion(string $plain): DOMElement
    {
        $plain = trim((string) preg_replace('/^\s*<\?xml[^>]*\?>/', '', $plain));

        try {
            $document = Xml::load($plain);
            $root = $document->documentElement;

            if ($root !== null && $root->namespaceURI === Xml::SAML && $root->localName === 'Assertion') {
                return $root;
            }
        } catch (InvalidResponse) {
            // The fragment is parsed again below with the namespace context restored.
        }

        $wrapper = '<wk:Wrapper xmlns:wk="urn:beziworld:wezel-krajowy"';

        foreach (['saml2' => Xml::SAML, 'saml2p' => Xml::SAMLP, 'ds' => Xml::DS, 'xenc' => Xml::XENC, 'naturalperson' => Xml::NATURAL_PERSON, 'eidas' => Xml::EIDAS, 'xsi' => Xml::XSI] as $prefix => $namespace) {
            $wrapper .= sprintf(' xmlns:%s="%s"', $prefix, $namespace);
        }

        try {
            $document = Xml::load($wrapper . '>' . $plain . '</wk:Wrapper>');
        } catch (InvalidResponse $exception) {
            throw DecryptionFailed::because('the decrypted content is not valid XML');
        }

        $assertions = $document->documentElement !== null ? Xml::children($document->documentElement, Xml::SAML, 'Assertion') : [];

        if (count($assertions) !== 1) {
            throw DecryptionFailed::because('the decrypted content is not a single saml2:Assertion');
        }

        return $assertions[0];
    }

    private static function algorithm(DOMElement $element): string
    {
        $method = Xml::child($element, Xml::XENC, 'EncryptionMethod');

        return $method !== null ? trim($method->getAttribute('Algorithm')) : '';
    }

    private static function cipherValue(DOMElement $element): string
    {
        $cipherData = Xml::child($element, Xml::XENC, 'CipherData');
        $value = $cipherData !== null ? Xml::text(Xml::child($cipherData, Xml::XENC, 'CipherValue')) : null;
        $decoded = $value !== null ? base64_decode((string) preg_replace('/\s+/', '', $value), true) : false;

        if ($decoded === false || $decoded === '') {
            throw DecryptionFailed::because('CipherValue is missing or not base64');
        }

        return $decoded;
    }
}
