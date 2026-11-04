<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Data\Identity;
use Beziworld\WezelKrajowy\Data\LogoutResult;
use Beziworld\WezelKrajowy\Enums\EidasAttribute;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Exceptions\AuthenticationRejected;
use Beziworld\WezelKrajowy\Support\Pesel;
use Carbon\CarbonImmutable;

it('validates PESEL checksums and extracts them from eIDAS identifiers', function (): void {
    expect(Pesel::isValid('86072500004'))->toBeTrue()
        ->and(Pesel::isValid('86072500005'))->toBeFalse()
        ->and(Pesel::isValid('8607250000'))->toBeFalse()
        ->and(Pesel::fromPersonIdentifier('86072500004'))->toBe('86072500004')
        ->and(Pesel::fromPersonIdentifier('PL/PL/86072500004'))->toBe('86072500004')
        ->and(Pesel::fromPersonIdentifier('DE/PL/1234567890'))->toBeNull();
});

it('orders levels of assurance', function (): void {
    expect(LevelOfAssurance::High->satisfies(LevelOfAssurance::Substantial))->toBeTrue()
        ->and(LevelOfAssurance::Low->satisfies(LevelOfAssurance::Substantial))->toBeFalse()
        ->and(LevelOfAssurance::fromName('HIGH'))->toBe(LevelOfAssurance::High)
        ->and(LevelOfAssurance::fromName('http://eidas.europa.eu/LoA/low'))->toBe(LevelOfAssurance::Low)
        ->and(LevelOfAssurance::fromName('medium'))->toBeNull();
});

it('round-trips an identity through its array form', function (): void {
    $identity = new Identity(
        firstName: 'Jan',
        familyName: 'Niezbędny',
        dateOfBirth: CarbonImmutable::parse('1986-07-25', Identity::TIMEZONE),
        personIdentifier: '86072500004',
        pesel: '86072500004',
        levelOfAssurance: LevelOfAssurance::Substantial,
        identityProvider: 'pz.gov.pl',
        nameId: 'name-id',
        nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        sessionIndex: '_ID-1',
        assertionId: '_ID-a',
        authenticatedAt: CarbonImmutable::parse('2026-11-04T10:00:00.123Z'),
        attributes: ['FirstName' => ['Jan'], 'BirthName' => ['Jan Kowalski']],
    );

    $restored = Identity::fromArray($identity->toArray());

    expect($restored)->toEqual($identity)
        ->and($restored->fullName())->toBe('Jan Niezbędny')
        ->and($restored->attribute(EidasAttribute::BirthName))->toBe('Jan Kowalski')
        ->and($restored->attribute('FirstName'))->toBe('Jan')
        ->and($restored->hasPesel())->toBeTrue()
        ->and($restored->satisfies(LevelOfAssurance::High))->toBeFalse()
        ->and($restored->dateOfBirth->timezoneName)->toBe('Europe/Warsaw');
});

it('explains documented validation error codes', function (): void {
    $exception = new AuthenticationRejected(
        ['urn:oasis:names:tc:SAML:2.0:status:Requester'],
        'Blad walidacji: 3001 brak wymaganego atrybutu',
    );

    expect($exception->errorCode())->toBe('3001')
        ->and($exception->errorDescription())->toBe('a mandatory attribute is not requested')
        ->and($exception->reason())->toBe('rejected')
        ->and($exception->getMessage())->toContain('Requester');

    $denied = new AuthenticationRejected(['urn:oasis:names:tc:SAML:2.0:status:Requester', 'urn:oasis:names:tc:SAML:2.0:status: RequestDenied']);

    expect($denied->isRequestDenied())->toBeTrue()
        ->and($denied->reason())->toBe('request_denied')
        ->and($denied->errorCode())->toBeNull();
});

it('interprets logout statuses', function (): void {
    expect((new LogoutResult('a', 'b', [LogoutResult::SUCCESS]))->successful())->toBeTrue()
        ->and((new LogoutResult('a', 'b', [LogoutResult::PARTIAL_LOGOUT]))->partial())->toBeTrue()
        ->and((new LogoutResult('a', 'b', ['urn:oasis:names:tc:SAML:2.0:status:Requester']))->successful())->toBeFalse();
});
