<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Security;

/**
 * Algorithm identifiers of XML Signature 1.1 and XML Encryption 1.1 used by
 * the login.gov.pl profile.
 */
final class Algorithm
{
    public const string EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    public const string EXC_C14N_WITH_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    public const string C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

    public const string C14N_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';

    public const string ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    public const string ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';

    public const string ECDSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';

    public const string ECDSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';

    public const string RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    public const string RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';

    public const string RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    public const string SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

    public const string SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

    public const string SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';

    public const string SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';

    public const string AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';

    public const string AES192_GCM = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';

    public const string AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';

    public const string KW_AES128 = 'http://www.w3.org/2001/04/xmlenc#kw-aes128';

    public const string KW_AES192 = 'http://www.w3.org/2001/04/xmlenc#kw-aes192';

    public const string KW_AES256 = 'http://www.w3.org/2001/04/xmlenc#kw-aes256';

    public const string ECDH_ES = 'http://www.w3.org/2009/xmlenc11#ECDH-ES';

    public const string CONCAT_KDF = 'http://www.w3.org/2009/xmlenc11#ConcatKDF';

    public const string RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    public const string RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';

    public const string MGF1_SHA1 = 'http://www.w3.org/2009/xmlenc11#mgf1sha1';

    public const string MGF1_SHA256 = 'http://www.w3.org/2009/xmlenc11#mgf1sha256';

    public const string MGF1_SHA384 = 'http://www.w3.org/2009/xmlenc11#mgf1sha384';

    public const string MGF1_SHA512 = 'http://www.w3.org/2009/xmlenc11#mgf1sha512';

    /**
     * Signature method URI to [key type, hash name]. SHA-1 based methods are
     * intentionally absent because login.gov.pl forbids them.
     *
     * @var array<string, array{0: 'ec'|'rsa', 1: string}>
     */
    public const array SIGNATURE_METHODS = [
        self::ECDSA_SHA256 => ['ec', 'sha256'],
        self::ECDSA_SHA384 => ['ec', 'sha384'],
        self::ECDSA_SHA512 => ['ec', 'sha512'],
        self::RSA_SHA256 => ['rsa', 'sha256'],
        self::RSA_SHA384 => ['rsa', 'sha384'],
        self::RSA_SHA512 => ['rsa', 'sha512'],
    ];

    /**
     * Digest method URI to hash name (SHA-1 excluded).
     *
     * @var array<string, string>
     */
    public const array DIGEST_METHODS = [
        self::SHA256 => 'sha256',
        self::SHA384 => 'sha384',
        self::SHA512 => 'sha512',
    ];

    /**
     * Canonicalization methods accepted in signatures.
     *
     * @var list<string>
     */
    public const array CANONICALIZATION_METHODS = [
        self::EXC_C14N,
        self::EXC_C14N_WITH_COMMENTS,
        self::C14N,
        self::C14N_WITH_COMMENTS,
    ];

    /**
     * AES-GCM content encryption URI to key length in bytes.
     *
     * @var array<string, int>
     */
    public const array GCM_METHODS = [
        self::AES128_GCM => 16,
        self::AES192_GCM => 24,
        self::AES256_GCM => 32,
    ];

    /**
     * AES key wrap URI to key length in bytes.
     *
     * @var array<string, int>
     */
    public const array KEY_WRAP_METHODS = [
        self::KW_AES128 => 16,
        self::KW_AES192 => 24,
        self::KW_AES256 => 32,
    ];

    /**
     * Inclusive namespace prefixes used by login.gov.pl in exclusive canonicalization.
     *
     * @var list<string>
     */
    public const array INCLUSIVE_PREFIXES = ['ds', 'saml2', 'saml2p', 'xenc'];

    /**
     * Hash name for a digest URI including SHA-1, which is acceptable only
     * where it is a parameter of RSA-OAEP rather than a signature digest.
     */
    public static function oaepHash(string $uri): ?string
    {
        return match ($uri) {
            self::SHA1, self::MGF1_SHA1 => 'sha1',
            self::SHA256, self::MGF1_SHA256 => 'sha256',
            self::SHA384, self::MGF1_SHA384 => 'sha384',
            self::SHA512, self::MGF1_SHA512 => 'sha512',
            default => null,
        };
    }
}
