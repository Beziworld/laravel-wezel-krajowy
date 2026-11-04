<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Exceptions\InvalidSignature;
use Beziworld\WezelKrajowy\Security\Algorithm;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Security\XmlSignature;
use Beziworld\WezelKrajowy\Tests\Support\Keys;

function signedMessage(string $key = 'idp', bool $emptyReference = false): DOMDocument
{
    $document = Xml::load(sprintf(
        '<saml2p:LogoutResponse xmlns:saml2p="%s" xmlns:saml2="%s" ID="ID-abc" Version="2.0"><saml2:Issuer>login.gov.pl</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status></saml2p:LogoutResponse>',
        Xml::SAMLP,
        Xml::SAML,
    ));

    XmlSignature::sign(documentRoot($document), Keys::pair($key), $emptyReference);

    return Xml::load((string) $document->saveXML());
}

function documentRoot(DOMDocument $document): DOMElement
{
    return $document->documentElement ?? throw new RuntimeException('empty');
}

it('signs with ECDSA P-256 in the login.gov.pl layout and verifies', function (): void {
    $document = signedMessage();
    $xml = (string) $document->saveXML();

    expect(XmlSignature::verify(documentRoot($document), [Keys::certificate('idp')])->fingerprint())->toBe(Keys::certificate('idp')->fingerprint())
        ->and($xml)->toContain('<ds:SignatureMethod Algorithm="' . Algorithm::ECDSA_SHA256 . '"/>')
        ->and($xml)->toContain('<ds:Reference URI="#ID-abc">')
        ->and($xml)->toContain('PrefixList="ds saml2 saml2p xenc"')
        ->and($xml)->toMatch('/<saml2:Issuer>login.gov.pl<\/saml2:Issuer><ds:Signature/');

    $value = base64_decode((string) $document->getElementsByTagNameNS(Xml::DS, 'SignatureValue')->item(0)?->textContent, true);
    expect(strlen((string) $value))->toBe(64);
});

it('signs and verifies with RSA-SHA256 keys', function (): void {
    $document = signedMessage('rsa-idp', true);

    expect(XmlSignature::verify(documentRoot($document), [Keys::certificate('idp'), Keys::certificate('rsa-idp')])->isRsa())->toBeTrue()
        ->and((string) $document->saveXML())->toContain(Algorithm::RSA_SHA256)
        ->and((string) $document->saveXML())->toContain('<ds:Reference URI="">');
});

it('detects content modified after signing', function (): void {
    $document = signedMessage();
    $document->getElementsByTagNameNS(Xml::SAML, 'Issuer')->item(0)->textContent = 'attacker';

    XmlSignature::verify(documentRoot($document), [Keys::certificate('idp')]);
})->throws(InvalidSignature::class, 'digest mismatch');

it('rejects a signature made with an untrusted key', function (): void {
    XmlSignature::verify(documentRoot(signedMessage('attacker')), [Keys::certificate('idp')]);
})->throws(InvalidSignature::class, 'does not match any trusted');

it('rejects a reference that points at another element', function (): void {
    $document = signedMessage();
    documentRoot($document)->setAttribute('ID', 'ID-other');

    XmlSignature::verify(documentRoot($document), [Keys::certificate('idp')]);
})->throws(InvalidSignature::class, 'does not point at the signed element');

it('rejects SHA-1 signature methods', function (): void {
    $xml = str_replace(Algorithm::ECDSA_SHA256, 'http://www.w3.org/2000/09/xmldsig#rsa-sha1', (string) signedMessage()->saveXML());

    XmlSignature::verify(documentRoot(Xml::load($xml)), [Keys::certificate('idp')]);
})->throws(InvalidSignature::class, 'forbidden signature method');

it('rejects unsigned elements and missing trust anchors', function (): void {
    $document = signedMessage();

    expect(fn() => XmlSignature::verify(documentRoot($document), []))->toThrow(InvalidSignature::class, 'no trusted')
        ->and(function (): void {
            $unsigned = Xml::load('<saml2p:LogoutResponse xmlns:saml2p="' . Xml::SAMLP . '" ID="x"/>');
            XmlSignature::verify(documentRoot($unsigned), [Keys::certificate('idp')]);
        })->toThrow(InvalidSignature::class, 'not signed');
});

it('rejects transforms outside the enveloped profile', function (): void {
    $xml = str_replace(Algorithm::ENVELOPED_SIGNATURE, 'http://www.w3.org/TR/1999/REC-xpath-19991116', (string) signedMessage()->saveXML());

    XmlSignature::verify(documentRoot(Xml::load($xml)), [Keys::certificate('idp')]);
})->throws(InvalidSignature::class, 'unsupported transform');

it('refuses XML with a DOCTYPE declaration', function (): void {
    Xml::load('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>');
})->throws(Beziworld\WezelKrajowy\Exceptions\InvalidResponse::class, 'DOCTYPE');
