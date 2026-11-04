<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Data\PendingRequest;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Beziworld\WezelKrajowy\Exceptions\ReplayDetected;
use Beziworld\WezelKrajowy\Saml\RequestStore;
use Beziworld\WezelKrajowy\Saml\ResponseProcessor;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Tests\Support\FakeLoginGovPl;
use Beziworld\WezelKrajowy\Tests\Support\Keys;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;
use Carbon\CarbonImmutable;

function artifactResponseElement(string $xml): DOMElement
{
    $element = Xml::load($xml)->getElementsByTagNameNS(Xml::SAMLP, 'ArtifactResponse')->item(0);

    return $element instanceof DOMElement ? $element : throw new RuntimeException('no ArtifactResponse');
}

/**
 * @return array{0: ResponseProcessor, 1: RequestStore, 2: PendingRequest}
 */
function processorWithPendingRequest(array $config = []): array
{
    $store = new RequestStore(cache()->store(), 900);
    $pending = new PendingRequest('ID-request', LevelOfAssurance::Substantial, FakeLoginGovPl::ACS, CarbonImmutable::now(), '/back');
    $store->put($pending);

    $processor = new ResponseProcessor(
        WezelKrajowyConfig::fromArray(array_replace_recursive((array) config('wezel-krajowy'), $config)),
        Keys::pair('sp-encryption'),
        $store,
    );

    return [$processor, $store, $pending];
}

it('turns a valid ArtifactResponse into an identity bound to its request', function (): void {
    [$processor] = processorWithPendingRequest();

    $result = $processor->process(artifactResponseElement(FakeLoginGovPl::artifactResponse('ID-resolve', 'ID-request')), 'ID-resolve', [Keys::certificate('idp')]);

    expect($result->request->returnTo)->toBe('/back')
        ->and($result->identity->pesel)->toBe('86072500004')
        ->and($result->identity->raw['request_id'])->toBe('ID-request')
        ->and($result->identity->attributes['PersonIdentifier'])->toBe(['86072500004']);
});

it('detects replay of the request and of the assertion', function (): void {
    [$processor, $store, $pending] = processorWithPendingRequest();
    $xml = FakeLoginGovPl::artifactResponse('ID-resolve', 'ID-request', ['assertion' => ['id' => '_ID-fixed']]);

    $processor->process(artifactResponseElement($xml), 'ID-resolve', [Keys::certificate('idp')]);

    expect(fn() => $processor->process(artifactResponseElement($xml), 'ID-resolve', [Keys::certificate('idp')]))
        ->toThrow(ReplayDetected::class, 'already completed');

    $store->put($pending);

    expect(fn() => $processor->process(artifactResponseElement($xml), 'ID-resolve', [Keys::certificate('idp')]))
        ->toThrow(ReplayDetected::class, 'already been used');
});

it('requires the ArtifactResponse to answer this ArtifactResolve', function (): void {
    [$processor] = processorWithPendingRequest();

    $processor->process(artifactResponseElement(FakeLoginGovPl::artifactResponse('ID-other', 'ID-request')), 'ID-resolve', [Keys::certificate('idp')]);
})->throws(InvalidResponse::class, 'ArtifactResolve ID');

it('enforces the identity provider issuer when configured', function (): void {
    [$processor] = processorWithPendingRequest(['idp' => ['entity_id' => 'https://int.login.gov.pl/login/metadata']]);

    $processor->process(artifactResponseElement(FakeLoginGovPl::artifactResponse('ID-resolve', 'ID-request')), 'ID-resolve', [Keys::certificate('idp')]);
})->throws(InvalidResponse::class, 'unexpected ArtifactResponse Issuer');

it('tolerates clock skew within the configured window', function (): void {
    [$processor] = processorWithPendingRequest();
    $xml = FakeLoginGovPl::artifactResponse('ID-resolve', 'ID-request', ['assertion' => ['not_before' => CarbonImmutable::now()->addSeconds(60)]]);

    expect($processor->process(artifactResponseElement($xml), 'ID-resolve', [Keys::certificate('idp')])->identity->firstName)->toBe('Jan');
});

it('consumes the pending request when login.gov.pl reports a failure', function (): void {
    [$processor, $store] = processorWithPendingRequest();
    $xml = FakeLoginGovPl::artifactResponse('ID-resolve', 'ID-request', ['status' => ['urn:oasis:names:tc:SAML:2.0:status:Requester', 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied']]);

    expect(fn() => $processor->process(artifactResponseElement($xml), 'ID-resolve', [Keys::certificate('idp')]))
        ->toThrow(Beziworld\WezelKrajowy\Exceptions\AuthenticationRejected::class, 'RequestDenied')
        ->and($store->pull('ID-request'))->toBeNull();
});
