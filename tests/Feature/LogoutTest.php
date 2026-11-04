<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Events\UserLoggedOut;
use Beziworld\WezelKrajowy\Exceptions\ApiException;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Beziworld\WezelKrajowy\Exceptions\InvalidSignature;
use Beziworld\WezelKrajowy\Facades\WezelKrajowy;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Security\XmlSignature;
use Beziworld\WezelKrajowy\Support\SessionState;
use Beziworld\WezelKrajowy\Tests\Support\FakeLoginGovPl;
use Beziworld\WezelKrajowy\Tests\Support\Keys;
use Beziworld\WezelKrajowy\Tests\TestCase;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;

/**
 * @param list<string> $status
 */
function fakeLogout(array $status = [FakeLoginGovPl::SUCCESS], string $key = 'idp'): void
{
    Http::fake([
        TestCase::SLO_URL => static fn(Request $request) => Http::response(FakeLoginGovPl::logoutResponse(FakeLoginGovPl::requestId($request->body()), $status, $key)),
    ]);
}

it('sends a signed LogoutRequest and logs the user out locally', function (): void {
    Event::fake([UserLoggedOut::class]);
    fakeLogout();
    $this->actingAs(new GenericUser(['id' => 7, 'remember_token' => null]));
    session()->put(SessionState::IDENTITY, sessionIdentity()->toArray());

    $this->post('/wezel-krajowy/logout')->assertRedirect('/');

    expect(Auth::check())->toBeFalse()
        ->and(session(SessionState::IDENTITY))->toBeNull();

    Event::assertDispatched(UserLoggedOut::class, static fn(UserLoggedOut $event): bool => $event->result?->successful() === true
        && $event->identity?->nameId === 'name-id-123'
        && $event->exception === null);

    Http::assertSent(static function (Request $request): bool {
        $document = Xml::load($request->body());
        $logout = $document->getElementsByTagNameNS(Xml::SAMLP, 'LogoutRequest')->item(0);

        return $request->url() === TestCase::SLO_URL
            && $logout instanceof DOMElement
            && $logout->getAttribute('Destination') === TestCase::SLO_URL
            && $document->getElementsByTagNameNS(Xml::SAML, 'NameID')->item(0)?->textContent === 'name-id-123'
            && $document->getElementsByTagNameNS(Xml::SAMLP, 'SessionIndex')->item(0)?->textContent === '_ID-session-1'
            && XmlSignature::verify($logout, [Keys::certificate('sp-signing')])->isEc();
    });
});

it('reports a partial logout', function (): void {
    fakeLogout(['urn:oasis:names:tc:SAML:2.0:status:Success', 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout']);

    $result = WezelKrajowy::logoutIdentity(sessionIdentity());

    expect($result->partial())->toBeTrue()
        ->and($result->successful())->toBeFalse()
        ->and($result->raw['issuer'])->toBe('login.gov.pl');
});

it('rejects a LogoutResponse signed by an untrusted key', function (): void {
    fakeLogout(key: 'attacker');

    WezelKrajowy::logoutIdentity(sessionIdentity());
})->throws(InvalidSignature::class);

it('still logs out locally when the logout service fails', function (): void {
    Event::fake([UserLoggedOut::class]);
    Http::fake([TestCase::SLO_URL => Http::response('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server</faultcode><faultstring>Internal error</faultstring></soap:Fault></soap:Body></soap:Envelope>', 500)]);
    $this->actingAs(new GenericUser(['id' => 7, 'remember_token' => null]));
    session()->put(SessionState::IDENTITY, sessionIdentity()->toArray());

    $this->post('/wezel-krajowy/logout')->assertRedirect('/');

    expect(Auth::check())->toBeFalse();
    Event::assertDispatched(UserLoggedOut::class, static fn(UserLoggedOut $event): bool => $event->result === null
        && $event->exception instanceof ApiException
        && $event->exception->httpStatus === 500
        && $event->exception->faultString === 'Internal error');
});

it('skips single logout when the session did not come from login.gov.pl', function (): void {
    Http::fake();
    $this->actingAs(new GenericUser(['id' => 7, 'remember_token' => null]));

    $this->post('/wezel-krajowy/logout')->assertRedirect('/');

    Http::assertNothingSent();
    expect(Auth::check())->toBeFalse();
});

it('maps SOAP faults, HTTP errors and non-SAML bodies to ApiException', function (mixed $response, string $message): void {
    Http::fake([TestCase::SLO_URL => $response]);

    expect(fn() => WezelKrajowy::logoutIdentity(sessionIdentity()))->toThrow(ApiException::class, $message);
})->with([
    'fault with 200' => [fn() => Http::response('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultstring>Bad request</faultstring></soap:Fault></soap:Body></soap:Envelope>'), 'Bad request'],
    'gateway error' => [fn() => Http::response('Bad gateway', 502), 'HTTP status 502'],
    'html body' => [fn() => Http::response('<html><body>maintenance</body></html>'), 'missing SOAP Envelope/Body'],
]);

it('rejects a LogoutResponse that answers another request', function (): void {
    Http::fake([TestCase::SLO_URL => Http::response(FakeLoginGovPl::logoutResponse('ID-other'))]);

    WezelKrajowy::logoutIdentity(sessionIdentity());
})->throws(InvalidResponse::class, 'InResponseTo');
