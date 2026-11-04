<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Data\Identity;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Tests\TestCase;
use Carbon\CarbonImmutable;

uses(TestCase::class)->in('Unit', 'Feature');

function sessionIdentity(LevelOfAssurance $loa = LevelOfAssurance::Substantial): Identity
{
    return new Identity(
        firstName: 'Jan',
        familyName: 'Niezbędny',
        dateOfBirth: CarbonImmutable::parse('1986-07-25', Identity::TIMEZONE),
        personIdentifier: '86072500004',
        pesel: '86072500004',
        levelOfAssurance: $loa,
        identityProvider: 'pz.gov.pl',
        nameId: 'name-id-123',
        nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        sessionIndex: '_ID-session-1',
        assertionId: '_ID-a',
        authenticatedAt: CarbonImmutable::now(),
    );
}
