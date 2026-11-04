<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Data\AuthenticationResult;
use Beziworld\WezelKrajowy\Data\PendingRequest;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Exceptions\DecryptionFailed;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Beziworld\WezelKrajowy\Exceptions\InvalidSignature;
use Beziworld\WezelKrajowy\Exceptions\ReplayDetected;
use Beziworld\WezelKrajowy\Exceptions\UserNotResolved;
use Beziworld\WezelKrajowy\Facades\WezelKrajowy;
use Beziworld\WezelKrajowy\Saml\RequestStore;
use Beziworld\WezelKrajowy\Saml\ResponseProcessor;
use Beziworld\WezelKrajowy\Security\Algorithm;
use Beziworld\WezelKrajowy\Security\Decrypter;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Security\XmlSignature;
use Beziworld\WezelKrajowy\Tests\Support\Encrypter;
use Beziworld\WezelKrajowy\Tests\Support\FakeLoginGovPl;
use Beziworld\WezelKrajowy\Tests\Support\Keys;
use Beziworld\WezelKrajowy\Tests\TestCase;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;
use Carbon\CarbonImmutable;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Http;

const SECURITY_ATTACKER_PESEL = '44051401458';

/**
 * Returns the first element of the SOAP Body, exactly as the SOAP transport does.
 */
function soapBodyElement(string $xml): DOMElement
{
    $body = Xml::load($xml)->getElementsByTagNameNS(Xml::SOAP, 'Body')->item(0);

    foreach ($body !== null ? $body->childNodes : [] as $child) {
        if ($child instanceof DOMElement) {
            return $child;
        }
    }

    throw new RuntimeException('empty SOAP Body');
}

/**
 * Processes a back-channel envelope against a freshly registered pending request.
 *
 * @param array<string, mixed> $options
 * @param array<string, mixed> $config
 */
function processEnvelope(array $options = [], array $config = []): AuthenticationResult
{
    $store = new RequestStore(cache()->store(), 900);
    $store->put(new PendingRequest('ID-request', LevelOfAssurance::Substantial, FakeLoginGovPl::ACS, CarbonImmutable::now(), '/back'));

    $processor = new ResponseProcessor(
        WezelKrajowyConfig::fromArray(array_replace_recursive((array) config('wezel-krajowy'), $config)),
        Keys::pair('sp-encryption'),
        $store,
    );

    return $processor->process(soapBodyElement(FakeLoginGovPl::artifactResponse('ID-resolve', 'ID-request', $options)), 'ID-resolve', [Keys::certificate('idp')]);
}

/**
 * EncryptedAssertion that an attacker can produce: valid XML Encryption for
 * the public encryption certificate of the service provider, with an
 * identity of the attacker's choice, but no signature of login.gov.pl.
 */
function attackerEncryptedAssertion(DOMDocument $target): DOMElement
{
    $xml = Encrypter::ecdhEs(FakeLoginGovPl::assertion('ID-request', ['attributes' => [
        'FirstName' => ['http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName', 'Mallory'],
        'FamilyName' => ['http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName', 'Attacker'],
        'PersonIdentifier' => ['http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier', SECURITY_ATTACKER_PESEL],
        'DateOfBirth' => ['http://eidas.europa.eu/attributes/naturalperson/DateOfBirth', '1944-05-14'],
    ]]), Keys::certificate('sp-encryption'));

    $root = Xml::load($xml)->documentElement ?? throw new RuntimeException('empty');
    $imported = $target->importNode($root, true);

    return $imported instanceof DOMElement ? $imported : throw new RuntimeException('import failed');
}

function firstElement(DOMDocument $document, string $namespace, string $localName): DOMElement
{
    $element = $document->getElementsByTagNameNS($namespace, $localName)->item(0);

    return $element instanceof DOMElement ? $element : throw new RuntimeException('missing ' . $localName);
}

/**
 * Signed LogoutResponse document used by the signature profile tests.
 */
function profileMessage(string $key = 'idp'): string
{
    $document = Xml::load(sprintf(
        '<saml2p:LogoutResponse xmlns:saml2p="%s" xmlns:saml2="%s" ID="ID-abc" Version="2.0"><saml2:Issuer>login.gov.pl</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status></saml2p:LogoutResponse>',
        Xml::SAMLP,
        Xml::SAML,
    ));

    XmlSignature::sign($document->documentElement ?? throw new RuntimeException('empty'), Keys::pair($key));

    return (string) $document->saveXML();
}

function verifyProfileMessage(string $xml): void
{
    XmlSignature::verify(Xml::load($xml)->documentElement ?? throw new RuntimeException('empty'), [Keys::certificate('idp')]);
}

// XML signature wrapping (XSW) and signature placement.

it('rejects XSW: a forged ArtifactResponse that wraps the signed original', function (): void {
    processEnvelope(['tamper' => static function (DOMDocument $document): void {
        $original = firstElement($document, Xml::SAMLP, 'ArtifactResponse');
        $forged = $original->cloneNode(true);
        assert($forged instanceof DOMElement);

        $response = Xml::child($forged, Xml::SAMLP, 'Response') ?? throw new RuntimeException('no Response');
        $encrypted = Xml::child($response, Xml::SAML, 'EncryptedAssertion') ?? throw new RuntimeException('no EncryptedAssertion');
        $response->replaceChild(attackerEncryptedAssertion($document), $encrypted);

        $original->parentNode?->replaceChild($forged, $original);
        $extensions = $document->createElementNS(Xml::SAMLP, 'saml2p:Extensions');
        $extensions->appendChild($original);
        $forged->insertBefore($extensions, $response);
    }]);
})->throws(InvalidSignature::class, 'digest mismatch');

it('rejects XSW: a forged sibling that reuses the ID of the signed ArtifactResponse', function (): void {
    processEnvelope(['tamper' => static function (DOMDocument $document): void {
        $original = firstElement($document, Xml::SAMLP, 'ArtifactResponse');
        $forged = $original->cloneNode(true);
        assert($forged instanceof DOMElement);

        $response = Xml::child($forged, Xml::SAMLP, 'Response') ?? throw new RuntimeException('no Response');
        $encrypted = Xml::child($response, Xml::SAML, 'EncryptedAssertion') ?? throw new RuntimeException('no EncryptedAssertion');
        $response->replaceChild(attackerEncryptedAssertion($document), $encrypted);
        $original->parentNode?->insertBefore($forged, $original);
    }]);
})->throws(InvalidSignature::class, 'digest mismatch');

it('rejects XSW: an attacker assertion injected next to the signed one', function (): void {
    processEnvelope(['tamper' => static function (DOMDocument $document): void {
        $response = firstElement($document, Xml::SAMLP, 'Response');
        $response->insertBefore(attackerEncryptedAssertion($document), Xml::child($response, Xml::SAML, 'EncryptedAssertion'));
    }]);
})->throws(InvalidSignature::class);

it('rejects XSW: a signature moved out of the element it signs', function (): void {
    processEnvelope(['tamper' => static function (DOMDocument $document): void {
        $artifactResponse = firstElement($document, Xml::SAMLP, 'ArtifactResponse');
        $signature = Xml::child($artifactResponse, Xml::DS, 'Signature') ?? throw new RuntimeException('no Signature');
        $extensions = $document->createElementNS(Xml::SAMLP, 'saml2p:Extensions');
        $artifactResponse->replaceChild($extensions, $signature);
        $extensions->appendChild($signature);
    }]);
})->throws(InvalidSignature::class, 'not signed');

it('binds the reference only to an unqualified ID attribute of the signed element', function (string $search, string $replace): void {
    verifyProfileMessage(str_replace($search, $replace, profileMessage()));
})->throws(InvalidSignature::class)->with([
    'ID renamed to Id' => [' ID="ID-abc"', ' Id="ID-abc"'],
    'ID moved to another namespace' => [' ID="ID-abc"', ' xmlns:x="urn:x" x:ID="ID-abc"'],
]);

it('rejects a Response with two encrypted assertions even when login.gov.pl signed it', function (): void {
    processEnvelope(['mutate' => static function (DOMDocument $document): void {
        firstElement($document, Xml::SAMLP, 'Response')->appendChild(attackerEncryptedAssertion($document));
    }]);
})->throws(InvalidResponse::class, 'exactly one encrypted assertion');

it('rejects a plain assertion placed next to the encrypted one', function (): void {
    processEnvelope(['mutate' => static function (DOMDocument $document): void {
        $plain = Xml::load(FakeLoginGovPl::assertion('ID-request'))->documentElement ?? throw new RuntimeException('empty');
        firstElement($document, Xml::SAMLP, 'Response')->appendChild($document->importNode($plain, true));
    }]);
})->throws(InvalidResponse::class, 'exactly one encrypted assertion');

it('rejects an ArtifactResponse that carries more than one Response', function (): void {
    processEnvelope(['mutate' => static function (DOMDocument $document): void {
        $artifactResponse = firstElement($document, Xml::SAMLP, 'ArtifactResponse');
        $artifactResponse->appendChild(firstElement($document, Xml::SAMLP, 'Response')->cloneNode(true));
    }, 'sign_inner' => false], ['security' => ['require_signed_response' => false]]);
})->throws(InvalidResponse::class, 'exactly one <Response>');

// Canonicalization, transforms and algorithm allow-lists.

it('refuses transforms, digests and signature methods outside the allow-list', function (string $search, string $replace, string $message): void {
    verifyProfileMessage(str_replace($search, $replace, profileMessage()));
})->with([
    'XSLT transform' => [Algorithm::ENVELOPED_SIGNATURE, 'http://www.w3.org/TR/1999/REC-xslt-19991116', 'unsupported transform'],
    'XPath Filter 2.0 transform' => [Algorithm::ENVELOPED_SIGNATURE, 'http://www.w3.org/2002/06/xmldsig-filter2', 'unsupported transform'],
    'HMAC signature method' => [Algorithm::ECDSA_SHA256, 'http://www.w3.org/2000/09/xmldsig#hmac-sha1', 'forbidden signature method'],
    'HMAC-SHA256 signature method' => [Algorithm::ECDSA_SHA256, 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256', 'forbidden signature method'],
    'SHA-1 digest' => [Algorithm::SHA256, Algorithm::SHA1, 'forbidden digest method'],
])->throws(InvalidSignature::class);

it('requires the enveloped-signature transform', function (): void {
    $xml = (string) preg_replace('#<ds:Transform Algorithm="' . preg_quote(Algorithm::ENVELOPED_SIGNATURE, '#') . '"/>#', '', profileMessage());

    verifyProfileMessage($xml);
})->throws(InvalidSignature::class, 'enveloped-signature transform');

it('ignores KeyInfo and trusts only the configured certificates', function (): void {
    $xml = profileMessage('attacker');

    expect($xml)->toContain('<ds:X509Certificate>' . Keys::certificate('attacker')->base64());

    verifyProfileMessage($xml);
})->throws(InvalidSignature::class, 'does not match any trusted');

it('reads the complete text when a comment is inserted into signed content', function (): void {
    $xml = str_replace('<saml2:Issuer>login.gov.pl</saml2:Issuer>', '<saml2:Issuer>login<!---->.gov.pl</saml2:Issuer>', profileMessage());
    $root = Xml::load($xml)->documentElement ?? throw new RuntimeException('empty');

    XmlSignature::verify($root, [Keys::certificate('idp')]);

    expect(Xml::text(Xml::child($root, Xml::SAML, 'Issuer')))->toBe('login.gov.pl');
});

// XML parser hardening.

it('refuses a UTF-16 encoded DOCTYPE that the byte-level check cannot see', function (): void {
    $xml = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>';
    $utf16 = "\xFF\xFE" . mb_convert_encoding($xml, 'UTF-16LE', 'UTF-8');

    expect(str_contains($utf16, '<!DOCTYPE'))->toBeFalse();

    Xml::load($utf16);
})->throws(InvalidResponse::class);

// Decryption.

it('rejects an ECDH-ES originator key that is not on the curve', function (): void {
    $document = Xml::load(Encrypter::ecdhEs(FakeLoginGovPl::assertion('ID-request'), Keys::certificate('sp-encryption')));
    $publicKey = firstElement($document, Xml::DSIG11, 'PublicKey');
    $point = (string) base64_decode($publicKey->textContent, true);
    $point[64] = chr(ord($point[64]) ^ 0x01);
    $publicKey->textContent = base64_encode($point);

    Decrypter::decryptAssertion($document->documentElement ?? throw new RuntimeException('empty'), Keys::pair('sp-encryption'));
})->throws(DecryptionFailed::class, 'not a valid point on the curve');

it('rejects an ECDH-ES originator key of a different size than the curve', function (): void {
    $document = Xml::load(Encrypter::ecdhEs(FakeLoginGovPl::assertion('ID-request'), Keys::certificate('sp-encryption')));
    $publicKey = firstElement($document, Xml::DSIG11, 'PublicKey');
    $point = (string) base64_decode($publicKey->textContent, true);
    $publicKey->textContent = base64_encode("\x04" . str_repeat("\x00", 16) . substr($point, 1, 32) . str_repeat("\x00", 16) . substr($point, 33));

    Decrypter::decryptAssertion($document->documentElement ?? throw new RuntimeException('empty'), Keys::pair('sp-encryption'));
})->throws(DecryptionFailed::class);

// Protocol checks.

it('requires InResponseTo in the bearer SubjectConfirmationData', function (): void {
    processEnvelope(['assertion' => ['in_response_to' => '']]);
})->throws(InvalidResponse::class, 'InResponseTo');

it('requires an Issuer in the assertion', function (): void {
    processEnvelope(['assertion' => ['issuer' => null]]);
})->throws(InvalidResponse::class, 'Assertion has no Issuer');

it('enforces the configured Issuer on the assertion', function (): void {
    processEnvelope(['assertion' => ['issuer' => 'https://idp.example.org']], ['idp' => ['entity_id' => 'login.gov.pl']]);
})->throws(InvalidResponse::class, 'unexpected Assertion Issuer');

it('does not let an unknown attribute shadow PersonIdentifier through its FriendlyName', function (): void {
    $result = processEnvelope(['assertion' => ['attributes' => [
        'Spoofed' => ['urn:example:custom:identifier', SECURITY_ATTACKER_PESEL, 'PersonIdentifier'],
        'FirstName' => ['http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName', 'Jan'],
        'FamilyName' => ['http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName', 'Nowak'],
        'PersonIdentifier' => ['http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier', '86072500004'],
        'DateOfBirth' => ['http://eidas.europa.eu/attributes/naturalperson/DateOfBirth', '1986-07-25'],
    ]]]);

    expect($result->identity->personIdentifier)->toBe('86072500004')
        ->and($result->identity->pesel)->toBe('86072500004')
        ->and($result->identity->attributes['urn:example:custom:identifier'])->toBe([SECURITY_ATTACKER_PESEL]);
});

it('rejects a mandatory attribute with more than one value', function (): void {
    processEnvelope(['assertion' => ['attributes' => [
        'FirstName' => ['http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName', 'Jan'],
        'FamilyName' => ['http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName', 'Nowak'],
        'PersonIdentifier' => ['http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier', SECURITY_ATTACKER_PESEL],
        'Second' => ['http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier', '86072500004', 'PersonIdentifier'],
        'DateOfBirth' => ['http://eidas.europa.eu/attributes/naturalperson/DateOfBirth', '1986-07-25'],
    ]]]);
})->throws(InvalidResponse::class, 'more than one value');

// Session binding through the public API.

/**
 * Fakes artifact resolution for the given request ID.
 */
function fakeResolutionFor(string $requestId): void
{
    Http::fake([
        TestCase::ARTIFACT_URL => static fn(ClientRequest $request) => Http::response(
            FakeLoginGovPl::artifactResponse(FakeLoginGovPl::requestId($request->body()), $requestId),
            200,
            ['Content-Type' => 'text/xml; charset=utf-8'],
        ),
    ]);
}

function requestWithSession(): Request
{
    $request = Request::create('/');
    $session = new Store('wezel-krajowy-test', new ArraySessionHandler(10));
    $session->start();
    $request->setLaravelSession($session);

    return $request;
}

it('binds artifacts resolved through the public API to the browser session', function (): void {
    $victim = requestWithSession();
    $attacker = requestWithSession();

    $message = WezelKrajowy::authnRequest('/orders', null, $attacker);
    fakeResolutionFor($message->request->id);

    WezelKrajowy::resolveArtifact(FakeLoginGovPl::ARTIFACT, $victim);
})->throws(ReplayDetected::class, 'not started in this browser session');

it('resolves an artifact through the public API in the session that started the login', function (): void {
    $request = requestWithSession();
    $message = WezelKrajowy::authnRequest('/orders', null, $request);
    fakeResolutionFor($message->request->id);

    expect(WezelKrajowy::resolveArtifact(FakeLoginGovPl::ARTIFACT, $request)->identity->pesel)->toBe('86072500004');
});

it('refuses session-less resolution unless session binding is disabled', function (): void {
    $message = WezelKrajowy::authnRequest('/orders');
    fakeResolutionFor($message->request->id);

    expect(fn() => WezelKrajowy::resolveArtifact(FakeLoginGovPl::ARTIFACT, Request::create('/')))->toThrow(ReplayDetected::class);
});

// Laravel integration.

it('never follows a foreign return URL after the login', function (string $returnTo): void {
    $html = (string) $this->get('/wezel-krajowy/login?return_to=' . urlencode($returnTo))->assertOk()->getContent();
    preg_match('/name="SAMLRequest" value="([^"]+)"/', $html, $match);
    preg_match('/ ID="([^"]+)"/', (string) base64_decode(html_entity_decode($match[1] ?? ''), true), $id);
    fakeResolutionFor($id[1] ?? '');

    $this->get('/wezel-krajowy/acs?SAMLart=' . urlencode(FakeLoginGovPl::ARTIFACT))->assertRedirect('/dashboard');
})->with([
    'protocol relative' => ['//evil.example'],
    'absolute foreign' => ['https://evil.example/'],
    'backslash' => ['/\\evil.example'],
    'userinfo' => ['https://localhost@evil.example/'],
    'javascript' => ['javascript:alert(1)'],
    'tab before slashes' => ["/\t/evil.example"],
    'scheme without slashes' => ['https:evil.example'],
]);

it('issues a new session identifier on login', function (): void {
    $this->get('/wezel-krajowy/login');
    $before = session()->getId();
    $html = (string) $this->get('/wezel-krajowy/login')->getContent();
    preg_match('/name="SAMLRequest" value="([^"]+)"/', $html, $match);
    preg_match('/ ID="([^"]+)"/', (string) base64_decode(html_entity_decode($match[1] ?? ''), true), $id);
    fakeResolutionFor($id[1] ?? '');

    $this->get('/wezel-krajowy/acs?SAMLart=' . urlencode(FakeLoginGovPl::ARTIFACT))->assertRedirect('/dashboard');

    expect(session()->getId())->not->toBe($before);
});

it('keeps the PESEL out of reported exceptions', function (): void {
    Exceptions::fake();
    WezelKrajowy::resolveUsersUsing(static fn(): null => null);
    $html = (string) $this->get('/wezel-krajowy/login')->getContent();
    preg_match('/name="SAMLRequest" value="([^"]+)"/', $html, $match);
    preg_match('/ ID="([^"]+)"/', (string) base64_decode(html_entity_decode($match[1] ?? ''), true), $id);
    fakeResolutionFor($id[1] ?? '');

    $this->get('/wezel-krajowy/acs?SAMLart=' . urlencode(FakeLoginGovPl::ARTIFACT))->assertRedirect('/login');

    Exceptions::assertReported(UserNotResolved::class);
    Exceptions::assertNotReported(static fn(UserNotResolved $exception): bool => str_contains($exception->getMessage(), '86072500004'));
});
