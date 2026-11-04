<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Exceptions\DecryptionFailed;
use Beziworld\WezelKrajowy\Security\AesKeyWrap;
use Beziworld\WezelKrajowy\Security\Algorithm;
use Beziworld\WezelKrajowy\Security\ConcatKdf;
use Beziworld\WezelKrajowy\Security\Decrypter;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Tests\Support\Encrypter;
use Beziworld\WezelKrajowy\Tests\Support\FakeLoginGovPl;
use Beziworld\WezelKrajowy\Tests\Support\Keys;

function encryptedAssertionElement(string $xml): DOMElement
{
    $root = Xml::load($xml)->documentElement;

    return $root instanceof DOMElement ? $root : throw new RuntimeException('no root');
}

it('wraps and unwraps keys with the RFC 3394 test vectors', function (string $kek, string $key, string $wrapped): void {
    expect(strtoupper(bin2hex(AesKeyWrap::wrap((string) hex2bin($kek), (string) hex2bin($key)))))->toBe($wrapped)
        ->and(bin2hex((string) AesKeyWrap::unwrap((string) hex2bin($kek), (string) hex2bin($wrapped))))->toBe(strtolower($key));
})->with([
    '128-bit KEK, 128-bit key' => ['000102030405060708090A0B0C0D0E0F', '00112233445566778899AABBCCDDEEFF', '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'],
    '256-bit KEK, 256-bit key' => ['000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F', '28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21'],
]);

it('rejects a wrapped key whose integrity check fails', function (): void {
    $wrapped = (string) hex2bin('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE6');

    expect(AesKeyWrap::unwrap((string) hex2bin('000102030405060708090A0B0C0D0E0F'), $wrapped))->toBeNull();
});

it('encodes ConcatKDF parameters exactly like the integration guide example', function (): void {
    expect(ConcatKdf::encodeParameter('localhost.wk.gov.pl'))->toBe('000000136C6F63616C686F73742E776B2E676F762E706C')
        ->and(ConcatKdf::encodeParameter('http://www.w3.org/2001/04/xmlenc#kw-aes128'))
        ->toBe('0000002A687474703A2F2F7777772E77332E6F72672F323030312F30342F786D6C656E63236B772D616573313238')
        ->and(ConcatKdf::decodeParameter('zz'))->toBeNull();
});

it('derives ConcatKDF output with a big-endian counter starting at one', function (): void {
    $shared = random_bytes(32);
    $info = 'algorithm|party-u|party-v';

    expect(ConcatKdf::derive($shared, $info, 32))->toBe(hash('sha256', "\x00\x00\x00\x01" . $shared . $info, true))
        ->and(strlen(ConcatKdf::derive($shared, $info, 48)))->toBe(48)
        ->and(substr(ConcatKdf::derive($shared, $info, 48), 32))->toBe(substr(hash('sha256', "\x00\x00\x00\x02" . $shared . $info, true), 0, 16));
});

it('decrypts an ECDH-ES / ConcatKDF / kw-aes256 / AES-256-GCM assertion', function (): void {
    $assertion = FakeLoginGovPl::assertion('ID-request-1');
    $encrypted = Encrypter::ecdhEs($assertion, Keys::certificate('sp-encryption'));

    $decrypted = Decrypter::decryptAssertion(encryptedAssertionElement($encrypted), Keys::pair('sp-encryption'));

    expect($decrypted->localName)->toBe('Assertion')
        ->and($decrypted->namespaceURI)->toBe(Xml::SAML)
        ->and($decrypted->getElementsByTagNameNS(Xml::SAML, 'AttributeValue')->item(0)?->textContent)->toBe('Jan');
});

it('accepts a 128-bit content key even when aes256-gcm is declared', function (): void {
    $encrypted = Encrypter::ecdhEs(FakeLoginGovPl::assertion('ID-request-1'), Keys::certificate('sp-encryption'), contentKeyLength: 16);

    expect(Decrypter::decryptAssertion(encryptedAssertionElement($encrypted), Keys::pair('sp-encryption'))->localName)->toBe('Assertion');
});

it('decrypts an RSA-OAEP key transport assertion', function (): void {
    $encrypted = Encrypter::rsaOaep(FakeLoginGovPl::assertion('ID-request-1'), Keys::certificate('rsa-encryption'));

    expect(Decrypter::decryptAssertion(encryptedAssertionElement($encrypted), Keys::pair('rsa-encryption'))->localName)->toBe('Assertion');
});

it('fails to decrypt an assertion encrypted for another key', function (): void {
    $encrypted = Encrypter::ecdhEs(FakeLoginGovPl::assertion('ID-request-1'), Keys::certificate('other-encryption'));

    Decrypter::decryptAssertion(encryptedAssertionElement($encrypted), Keys::pair('sp-encryption'));
})->throws(DecryptionFailed::class, 'integrity check failed');

it('detects a modified cipher text through the GCM tag', function (): void {
    $encrypted = Encrypter::ecdhEs(FakeLoginGovPl::assertion('ID-request-1'), Keys::certificate('sp-encryption'));
    $document = Xml::load($encrypted);
    $values = $document->getElementsByTagNameNS(Xml::XENC, 'CipherValue');
    $last = $values->item($values->length - 1);
    $bytes = (string) base64_decode((string) $last?->textContent, true);
    $bytes[20] = $bytes[20] === 'A' ? 'B' : 'A';
    $last->textContent = base64_encode($bytes);

    Decrypter::decryptAssertion(encryptedAssertionElement((string) $document->saveXML()), Keys::pair('sp-encryption'));
})->throws(DecryptionFailed::class, 'authentication tag');

it('refuses content encryption algorithms outside AES-GCM', function (): void {
    $encrypted = str_replace(Algorithm::AES256_GCM, 'http://www.w3.org/2001/04/xmlenc#aes256-cbc', Encrypter::ecdhEs(FakeLoginGovPl::assertion('ID-1'), Keys::certificate('sp-encryption')));

    Decrypter::decryptAssertion(encryptedAssertionElement($encrypted), Keys::pair('sp-encryption'));
})->throws(DecryptionFailed::class, 'unsupported content encryption algorithm');

it('requires an EC key for ECDH-ES', function (): void {
    $encrypted = Encrypter::ecdhEs(FakeLoginGovPl::assertion('ID-1'), Keys::certificate('sp-encryption'));

    Decrypter::decryptAssertion(encryptedAssertionElement($encrypted), Keys::pair('rsa-encryption'));
})->throws(DecryptionFailed::class, 'ECDH-ES requires an EC encryption key');
