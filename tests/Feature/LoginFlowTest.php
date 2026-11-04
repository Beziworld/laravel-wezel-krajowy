<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Data\Identity;
use Beziworld\WezelKrajowy\Events\AuthenticationFailed;
use Beziworld\WezelKrajowy\Events\UserAuthenticated;
use Beziworld\WezelKrajowy\Exceptions\AuthenticationRejected;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Beziworld\WezelKrajowy\Exceptions\InvalidSignature;
use Beziworld\WezelKrajowy\Exceptions\ReplayDetected;
use Beziworld\WezelKrajowy\Exceptions\UserNotResolved;
use Beziworld\WezelKrajowy\Facades\WezelKrajowy;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Security\XmlSignature;
use Beziworld\WezelKrajowy\Support\SessionState;
use Beziworld\WezelKrajowy\Tests\Support\FakeLoginGovPl;
use Beziworld\WezelKrajowy\Tests\Support\Keys;
use Beziworld\WezelKrajowy\Tests\TestCase;
use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;

/**
 * Starts a login through the route and returns the AuthnRequest ID.
 */
function startLogin(TestCase $test, string $query = '?return_to=/orders'): string
{
    $html = (string) $test->get('/wezel-krajowy/login' . $query)->assertOk()->getContent();
    preg_match('/name="SAMLRequest" value="([^"]+)"/', $html, $match);
    $xml = (string) base64_decode(html_entity_decode($match[1] ?? ''), true);
    preg_match('/ ID="([^"]+)"/', $xml, $id);

    return $id[1] ?? '';
}

/**
 * Fakes the artifact resolution service with a response built for the given request.
 *
 * @param array<string, mixed> $options
 */
function fakeArtifactResolution(string $requestId, array $options = []): void
{
    Http::fake([
        TestCase::ARTIFACT_URL => static fn(Request $request) => Http::response(
            FakeLoginGovPl::artifactResponse(FakeLoginGovPl::requestId($request->body()), $requestId, $options),
            200,
            ['Content-Type' => 'text/xml; charset=utf-8'],
        ),
    ]);
}

function loginAs(int $id = 7): void
{
    WezelKrajowy::resolveUsersUsing(static fn(Identity $identity): GenericUser => new GenericUser(['id' => $id, 'pesel' => $identity->pesel]));
}

it('renders a self-submitting AuthnRequest form and remembers the request', function (): void {
    $response = $this->get('/wezel-krajowy/login?return_to=/orders&loa=high');
    $html = (string) $response->getContent();

    preg_match('/name="SAMLRequest" value="([^"]+)"/', $html, $match);
    $xml = (string) base64_decode(html_entity_decode($match[1]), true);
    $document = Xml::load($xml);
    $root = $document->documentElement;
    $id = (string) $root?->getAttribute('ID');

    $response->assertOk()->assertHeader('Cache-Control');
    expect($html)->toContain('action="' . TestCase::SSO_URL . '"')
        ->and($html)->toContain('document.forms[0].submit()')
        ->and($root?->getAttribute('AssertionConsumerServiceURL'))->toBe(FakeLoginGovPl::ACS)
        ->and($xml)->toContain('http://eidas.europa.eu/LoA/high')
        ->and(XmlSignature::verify($root, [Keys::certificate('sp-signing')])->isEc())->toBeTrue()
        ->and(session(SessionState::PENDING))->toBe([$id])
        ->and(cache()->get('wezel-krajowy:request:' . $id)['return_to'])->toBe('/orders');
});

it('never lowers the configured level of assurance and ignores foreign return URLs', function (): void {
    $id = startLogin($this, '?loa=low&return_to=https://evil.example/steal');
    $pending = cache()->get('wezel-krajowy:request:' . $id);

    expect($pending['loa'])->toBe('http://eidas.europa.eu/LoA/substantial')
        ->and($pending['return_to'])->toBeNull();
});

it('bounces the cross-site POST to a GET on the assertion consumer', function (): void {
    $this->post('/wezel-krajowy/acs', ['SAMLart' => FakeLoginGovPl::ARTIFACT, 'RelayState' => 'abc'])
        ->assertStatus(303)
        ->assertRedirect(FakeLoginGovPl::ACS . '?SAMLart=' . urlencode(FakeLoginGovPl::ARTIFACT) . '&RelayState=abc');

    $this->post('/wezel-krajowy/acs')->assertStatus(400);
});

it('resolves the artifact, logs the user in and announces the identity', function (): void {
    Event::fake([UserAuthenticated::class]);
    loginAs();
    $requestId = startLogin($this);
    fakeArtifactResolution($requestId);

    $this->get('/wezel-krajowy/acs?SAMLart=' . urlencode(FakeLoginGovPl::ARTIFACT))->assertRedirect('/orders');

    expect(Auth::id())->toBe(7)
        ->and(WezelKrajowy::identity()?->pesel)->toBe('86072500004')
        ->and(session(SessionState::PENDING))->toBe([]);

    Event::assertDispatched(UserAuthenticated::class, static fn(UserAuthenticated $event): bool => $event->identity->firstName === 'Jan'
        && $event->identity->familyName === 'Niezbędny'
        && $event->identity->dateOfBirth->toDateString() === '1986-07-25'
        && $event->identity->identityProvider === 'pz.gov.pl'
        && $event->identity->sessionIndex === '_ID-session-1'
        && $event->user?->getAuthIdentifier() === 7);

    Http::assertSent(static function (Request $request): bool {
        $document = Xml::load($request->body());
        $resolve = $document->getElementsByTagNameNS(Xml::SAMLP, 'ArtifactResolve')->item(0);

        return $request->url() === TestCase::ARTIFACT_URL
            && $request->method() === 'POST'
            && $request->hasHeader('SOAPAction', '"http://www.oasis-open.org/committees/security"')
            && str_starts_with($request->header('Content-Type')[0] ?? '', 'text/xml')
            && $document->getElementsByTagNameNS(Xml::SAMLP, 'Artifact')->item(0)?->textContent === FakeLoginGovPl::ARTIFACT
            && $document->getElementsByTagNameNS(Xml::SAML, 'Issuer')->item(0)?->textContent === FakeLoginGovPl::ENTITY_ID
            && $resolve instanceof DOMElement
            && XmlSignature::verify($resolve, [Keys::certificate('sp-signing')])->isEc();
    });
});

it('stores the identity without a resolver and leaves login to the application', function (): void {
    Event::fake([UserAuthenticated::class]);
    $requestId = startLogin($this, '');
    fakeArtifactResolution($requestId, ['assertion' => ['loa' => 'http://eidas.europa.eu/LoA/high']]);

    $this->get('/wezel-krajowy/acs?SAMLart=' . urlencode(FakeLoginGovPl::ARTIFACT))->assertRedirect('/dashboard');

    expect(Auth::check())->toBeFalse()
        ->and(WezelKrajowy::identity()?->levelOfAssurance->shortName())->toBe('high');
    Event::assertDispatched(UserAuthenticated::class, static fn(UserAuthenticated $event): bool => $event->user === null);
});

it('accepts an RSA-OAEP encrypted and individually signed assertion', function (): void {
    config()->set('wezel-krajowy.sp.encryption.key', Keys::pem('rsa-encryption')['key']);
    config()->set('wezel-krajowy.sp.encryption.certificate', Keys::pem('rsa-encryption')['certificate']);
    config()->set('wezel-krajowy.idp.certificates', [Keys::pem('idp')['certificate'], Keys::pem('rsa-idp')['certificate']]);
    app()->forgetInstance(Beziworld\WezelKrajowy\WezelKrajowyConfig::class);
    app()->forgetInstance(Beziworld\WezelKrajowy\WezelKrajowy::class);
    WezelKrajowy::clearResolvedInstances();

    $requestId = startLogin($this);
    fakeArtifactResolution($requestId, ['encrypt' => 'rsa', 'recipient_key' => 'rsa-encryption', 'outer_key' => 'rsa-idp', 'sign_assertion' => true]);

    $this->get('/wezel-krajowy/acs?SAMLart=' . urlencode(FakeLoginGovPl::ARTIFACT))->assertRedirect('/orders');

    expect(WezelKrajowy::identity()?->personIdentifier)->toBe('86072500004');
});

/**
 * Runs the flow with a manipulated response and returns the flashed failure reason.
 *
 * @param array<string, mixed> $options
 */
function failingLogin(TestCase $test, array $options, ?Closure $before = null): string
{
    Event::fake([AuthenticationFailed::class, UserAuthenticated::class]);
    loginAs();
    $requestId = startLogin($test);
    fakeArtifactResolution($requestId, $options);

    if ($before !== null) {
        $before($requestId);
    }

    $test->get('/wezel-krajowy/acs?SAMLart=' . urlencode(FakeLoginGovPl::ARTIFACT))
        ->assertRedirect('/login')
        ->assertSessionHas('wezel_krajowy_error');

    expect(Auth::check())->toBeFalse();
    Event::assertNotDispatched(UserAuthenticated::class);

    return (string) session('wezel_krajowy_error');
}

it('rejects responses that fail a security check', function (array $options, string $exception, string $reason): void {
    expect(failingLogin($this, $options))->toBe($reason);

    Event::assertDispatched(AuthenticationFailed::class, static fn(AuthenticationFailed $event): bool => $event->exception instanceof $exception);
})->with([
    'unsigned ArtifactResponse' => [['sign_outer' => false], InvalidSignature::class, 'invalid_signature'],
    'ArtifactResponse signed by an untrusted key' => [['outer_key' => 'attacker'], InvalidSignature::class, 'invalid_signature'],
    'unsigned inner Response' => [['sign_inner' => false], InvalidSignature::class, 'invalid_signature'],
    'modified after signing' => [['tamper' => static function (DOMDocument $document): void {
        $document->getElementsByTagNameNS(Xml::SAML, 'Issuer')->item(1)->textContent = 'evil';
    }], InvalidSignature::class, 'invalid_signature'],
    'assertion for another request' => [['response_in_response_to' => null, 'assertion' => ['in_response_to' => 'ID-unknown']], ReplayDetected::class, 'replay'],
    'subject confirmation for another request' => [['assertion' => ['in_response_to' => 'ID-other']], InvalidResponse::class, 'invalid_response'],
    'expired assertion' => [['assertion' => ['confirmation_not_on_or_after' => CarbonImmutable::now()->subMinutes(10)]], InvalidResponse::class, 'invalid_response'],
    'expired conditions' => [['assertion' => ['not_on_or_after' => CarbonImmutable::now()->subMinutes(10)]], InvalidResponse::class, 'invalid_response'],
    'not yet valid' => [['assertion' => ['not_before' => CarbonImmutable::now()->addMinutes(10)]], InvalidResponse::class, 'invalid_response'],
    'wrong audience' => [['assertion' => ['audience' => 'https://other.example.pl']], InvalidResponse::class, 'invalid_response'],
    'wrong recipient' => [['assertion' => ['recipient' => 'https://other.example.pl/acs']], InvalidResponse::class, 'invalid_response'],
    'wrong destination' => [['destination' => 'https://other.example.pl/acs'], InvalidResponse::class, 'invalid_response'],
    'level of assurance too low' => [['assertion' => ['loa' => 'http://eidas.europa.eu/LoA/low']], InvalidResponse::class, 'invalid_response'],
    'unencrypted assertion' => [['encrypt' => 'none'], InvalidResponse::class, 'invalid_response'],
    'missing mandatory attribute' => [['assertion' => ['attributes' => [
        'FirstName' => ['http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName', 'Jan'],
        'FamilyName' => ['http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName', 'Nowak'],
        'DateOfBirth' => ['http://eidas.europa.eu/attributes/naturalperson/DateOfBirth', '1986-07-25'],
    ]]], InvalidResponse::class, 'invalid_response'],
    'encrypted for another key' => [['recipient_key' => 'other-encryption'], Beziworld\WezelKrajowy\Exceptions\DecryptionFailed::class, 'decryption'],
    'identity provider failure' => [['status' => ['urn:oasis:names:tc:SAML:2.0:status:Responder', AuthenticationRejected::AUTHN_FAILED], 'status_message' => 'Bledne dane'], AuthenticationRejected::class, 'authn_failed'],
    'artifact not resolved' => [['with_response' => false], InvalidResponse::class, 'invalid_response'],
]);

it('rejects a response that answers a request from another browser session', function (): void {
    expect(failingLogin($this, [], static fn() => session()->forget(SessionState::PENDING)))->toBe('replay');
});

it('refuses the login when the resolver finds no account', function (): void {
    Event::fake([AuthenticationFailed::class]);
    WezelKrajowy::resolveUsersUsing(static fn(Identity $identity): ?GenericUser => null);
    $requestId = startLogin($this);
    fakeArtifactResolution($requestId);

    $this->get('/wezel-krajowy/acs?SAMLart=' . urlencode(FakeLoginGovPl::ARTIFACT))
        ->assertRedirect('/login')
        ->assertSessionHas('wezel_krajowy_error', 'user_not_found');

    Event::assertDispatched(AuthenticationFailed::class, static fn(AuthenticationFailed $event): bool => $event->exception instanceof UserNotResolved
        && $event->identity?->pesel === '86072500004');
});

it('rejects malformed artifacts without calling login.gov.pl', function (): void {
    Http::fake();

    expect(fn() => WezelKrajowy::resolveArtifact('not-an-artifact'))->toThrow(InvalidResponse::class, 'type 0x0004');
    Http::assertNothingSent();
});
