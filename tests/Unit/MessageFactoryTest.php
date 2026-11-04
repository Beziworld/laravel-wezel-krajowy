<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Enums\EidasAttribute;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Saml\MessageFactory;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Security\XmlSignature;
use Beziworld\WezelKrajowy\Tests\Support\Keys;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;
use Carbon\CarbonImmutable;

function messageFactory(array $overrides = []): MessageFactory
{
    $config = WezelKrajowyConfig::fromArray(array_replace_recursive([
        'environment' => 'production-private',
        'sp' => [
            'entity_id' => 'https://sp.example.pl',
            'provider_name' => 'Sklep & Co',
            'type' => 'private',
            'signing' => ['key' => 'unused'],
            'encryption' => ['key' => 'unused'],
        ],
        'authn' => ['attributes' => ['BirthName']],
    ], $overrides));

    return new MessageFactory($config, Keys::pair('sp-signing'));
}

it('builds the AuthnRequest exactly in the documented shape', function (): void {
    $xml = messageFactory()->authnRequest('ID-123', 'https://sp.example.pl/acs', LevelOfAssurance::High, CarbonImmutable::parse('2026-01-02 03:04:05.678', 'UTC'));
    $document = Xml::load($xml);
    $root = $document->documentElement;

    expect($xml)->toStartWith('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
        ->and($root?->localName)->toBe('AuthnRequest')
        ->and($root?->getAttribute('AssertionConsumerServiceURL'))->toBe('https://sp.example.pl/acs')
        ->and($root?->getAttribute('Destination'))->toBe('https://podmiotyzewnetrzne.login.gov.pl/login/SingleSignOnService')
        ->and($root?->getAttribute('ForceAuthn'))->toBe('true')
        ->and($root?->getAttribute('IssueInstant'))->toBe('2026-01-02T03:04:05.678Z')
        ->and($root?->getAttribute('ProtocolBinding'))->toBe('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact')
        ->and($root?->getAttribute('ProviderName'))->toBe('Sklep & Co')
        ->and($xml)->toContain('ProviderName="Sklep &amp; Co"')
        ->and($xml)->toContain('<eidas:SPType>private</eidas:SPType>')
        ->and($xml)->toContain('<saml2p:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>')
        ->and($xml)->toContain('<saml2p:RequestedAuthnContext Comparison="minimum"><saml2:AuthnContextClassRef>http://eidas.europa.eu/LoA/high</saml2:AuthnContextClassRef>')
        ->and(XmlSignature::verify($root, [Keys::certificate('sp-signing')])->isEc())->toBeTrue();

    $order = [];
    foreach ($root?->attributes ?? [] as $attribute) {
        $order[] = $attribute->name;
    }
    expect($order)->toBe(['AssertionConsumerServiceURL', 'Destination', 'ForceAuthn', 'ID', 'IssueInstant', 'ProtocolBinding', 'ProviderName', 'Version']);

    $requested = [];
    foreach ($document->getElementsByTagNameNS(Xml::EIDAS, 'RequestedAttribute') as $attribute) {
        $requested[$attribute->getAttribute('FriendlyName')] = $attribute->getAttribute('isRequired');
    }
    expect($requested)->toBe(['FamilyName' => 'true', 'FirstName' => 'true', 'DateOfBirth' => 'true', 'PersonIdentifier' => 'true', 'BirthName' => 'false']);

    $children = [];
    foreach ($root?->childNodes ?? [] as $child) {
        $children[] = $child->localName;
    }
    expect($children)->toBe(['Issuer', 'Signature', 'Extensions', 'NameIDPolicy', 'RequestedAuthnContext']);
});

it('wraps a signed ArtifactResolve in a SOAP envelope', function (): void {
    $xml = messageFactory()->artifactResolve('ID-res', ' AAQAAcnceygFBb+m6oU0QfFClgJEIo9xVz7eKhr4hDP11aX2WDl2yxUS+7A=', CarbonImmutable::now());
    $document = Xml::load($xml);
    $resolve = $document->getElementsByTagNameNS(Xml::SAMLP, 'ArtifactResolve')->item(0);

    expect($document->documentElement?->localName)->toBe('Envelope')
        ->and($document->documentElement?->namespaceURI)->toBe(Xml::SOAP)
        ->and($resolve)->toBeInstanceOf(DOMElement::class)
        ->and($document->getElementsByTagNameNS(Xml::SAMLP, 'Artifact')->item(0)?->textContent)->toBe('AAQAAcnceygFBb+m6oU0QfFClgJEIo9xVz7eKhr4hDP11aX2WDl2yxUS+7A=')
        ->and($xml)->toContain('<ds:Reference URI="#ID-res">')
        ->and(XmlSignature::verify($resolve, [Keys::certificate('sp-signing')])->isEc())->toBeTrue();
});

it('builds a signed LogoutRequest with NameID and SessionIndex', function (): void {
    $xml = messageFactory(['environment' => 'integration'])->logoutRequest('ID-lo', 'name-id', null, '_ID-session', CarbonImmutable::now());
    $document = Xml::load($xml);
    $request = $document->getElementsByTagNameNS(Xml::SAMLP, 'LogoutRequest')->item(0);

    expect($request?->getAttribute('Destination'))->toBe('https://int.login.gov.pl/login-services/singleLogoutService')
        ->and($document->getElementsByTagNameNS(Xml::SAML, 'NameID')->item(0)?->getAttribute('Format'))->toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified')
        ->and($document->getElementsByTagNameNS(Xml::SAMLP, 'SessionIndex')->item(0)?->textContent)->toBe('_ID-session')
        ->and(XmlSignature::verify($request, [Keys::certificate('sp-signing')]))->not->toBeNull();
});

it('requests the mandatory attributes before configured optional ones', function (): void {
    $config = WezelKrajowyConfig::fromArray([
        'sp' => ['entity_id' => 'x', 'signing' => ['key' => 'k'], 'encryption' => ['key' => 'k']],
        'authn' => ['attributes' => ['CurrentAddress', 'FirstName', 'gender']],
    ]);

    expect($config->requestedAttributes())->toBe([
        EidasAttribute::FamilyName,
        EidasAttribute::FirstName,
        EidasAttribute::DateOfBirth,
        EidasAttribute::PersonIdentifier,
        EidasAttribute::CurrentAddress,
        EidasAttribute::Gender,
    ]);
});
