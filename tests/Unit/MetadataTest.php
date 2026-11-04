<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Saml\Metadata;
use Beziworld\WezelKrajowy\Security\Certificate;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Security\XmlSignature;
use Beziworld\WezelKrajowy\Tests\Support\Keys;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;

function intMetadata(): string
{
    return (string) file_get_contents(__DIR__ . '/../Fixtures/int-login-gov-pl-metadata.xml');
}

it('parses the captured int.login.gov.pl metadata', function (): void {
    $metadata = Metadata::parseIdp(intMetadata());

    expect($metadata->entityId)->toBe('https://int.login.gov.pl/login/metadata')
        ->and($metadata->ssoUrl)->toBe('https://int.login.gov.pl/login/SingleSignOnService')
        ->and($metadata->artifactResolutionUrl)->toBe('https://int.login.gov.pl/login-services/idpArtifactResolutionService')
        ->and($metadata->singleLogoutUrl)->toBe('https://int.login.gov.pl/login-services/singleLogoutService')
        ->and($metadata->signingCertificates)->toHaveCount(2)
        ->and($metadata->signingMethods)->toContain('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256')
        ->and($metadata->attributes)->toHaveKey('PersonIdentifier')
        ->and($metadata->nameIdFormats)->toContain('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified')
        ->and($metadata->spType)->toBe('public');

    $kinds = array_map(static fn(string $der): string => Certificate::load($der)->isEc() ? 'EC' : 'RSA', $metadata->signingCertificates);
    expect($kinds)->toEqualCanonicalizing(['EC', 'RSA']);
});

it('verifies the real ECDSA signatures produced by login.gov.pl', function (): void {
    $document = Xml::load(intMetadata());
    $root = $document->documentElement;
    $signer = Certificate::load((string) $document->getElementsByTagNameNS(Xml::DS, 'X509Certificate')->item(0)?->textContent);

    expect(XmlSignature::verify($root, [Keys::certificate('idp'), $signer])->subject())->toContain('WK_SIG_EC')
        ->and(XmlSignature::verify(Xml::single($root, Xml::MD, 'SPSSODescriptor'), [$signer])->isEc())->toBeTrue();
});

it('builds service provider metadata with both certificates and the artifact consumer', function (): void {
    $config = WezelKrajowyConfig::fromArray([
        'sp' => ['entity_id' => 'https://sp.example.pl', 'type' => 'private', 'signing' => ['key' => 'k'], 'encryption' => ['key' => 'k']],
    ]);

    $xml = Metadata::serviceProvider($config, 'https://sp.example.pl/acs', Keys::certificate('sp-signing'), Keys::certificate('sp-encryption'));
    $root = Xml::load($xml)->documentElement;

    expect($root?->getAttribute('entityID'))->toBe('https://sp.example.pl')
        ->and($xml)->toContain('<md:KeyDescriptor use="signing">')
        ->and($xml)->toContain('<md:KeyDescriptor use="encryption">')
        ->and($xml)->toContain(Keys::certificate('sp-encryption')->base64())
        ->and($xml)->toContain('Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://sp.example.pl/acs"')
        ->and($xml)->toContain('<eidas:SPType>private</eidas:SPType>')
        ->and($xml)->not->toContain('PRIVATE KEY');
});
