<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Exceptions\ApiException;
use Beziworld\WezelKrajowy\Exceptions\InvalidConfiguration;
use Beziworld\WezelKrajowy\Facades\WezelKrajowy;
use Beziworld\WezelKrajowy\Support\SessionState;
use Beziworld\WezelKrajowy\Tests\Support\Keys;
use Beziworld\WezelKrajowy\WezelKrajowy as WezelKrajowyService;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;
use Carbon\CarbonImmutable;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

function reloadService(): void
{
    app()->forgetInstance(WezelKrajowyConfig::class);
    app()->forgetInstance(WezelKrajowyService::class);
    WezelKrajowy::clearResolvedInstances();
}

function metadataFixture(): string
{
    return (string) file_get_contents(__DIR__ . '/../Fixtures/int-login-gov-pl-metadata.xml');
}

it('serves the service provider metadata', function (): void {
    $response = $this->get('/wezel-krajowy/metadata');

    $response->assertOk()->assertHeader('Content-Type', 'application/samlmetadata+xml; charset=UTF-8');
    expect($response->getContent())->toContain('entityID="https://sp.example.pl"')
        ->and($response->getContent())->toContain('Location="http://localhost/wezel-krajowy/acs"')
        ->and($response->getContent())->toContain(Keys::certificate('sp-signing')->base64());
});

it('protects routes with the level of assurance middleware', function (): void {
    Route::middleware(['web', 'wezel-krajowy.loa:high'])->get('/secure', static fn(): string => 'secret');

    $this->get('/secure')->assertRedirect('http://localhost/wezel-krajowy/login?loa=high&return_to=%2Fsecure');
    $this->getJson('/secure')->assertStatus(401);

    session()->put(SessionState::IDENTITY, sessionIdentity(LevelOfAssurance::Substantial)->toArray());
    $this->get('/secure')->assertRedirect();

    session()->put(SessionState::IDENTITY, sessionIdentity(LevelOfAssurance::High)->toArray());
    $this->get('/secure')->assertOk()->assertSee('secret');
});

it('reads trusted certificates from the environment metadata when allowed', function (): void {
    config()->set('wezel-krajowy.idp.certificates', []);
    config()->set('wezel-krajowy.idp.trust_metadata', true);
    reloadService();
    CarbonImmutable::setTestNow('2026-11-04 12:00:00');
    Http::fake(['https://int.login.gov.pl/login/metadata' => Http::response(metadataFixture(), 200, ['Content-Type' => 'application/xml'])]);

    $subjects = array_map(static fn($certificate): string => $certificate->subject(), WezelKrajowy::certificates()->all());
    reloadService();
    WezelKrajowy::certificates()->all();

    expect($subjects)->toHaveCount(2)
        ->and(implode(' ', $subjects))->toContain('WK_SIG_EC');
    Http::assertSentCount(1);

    CarbonImmutable::setTestNow();
});

it('refuses to run without pinned certificates unless metadata trust is enabled', function (): void {
    config()->set('wezel-krajowy.idp.certificates', []);
    reloadService();

    WezelKrajowy::certificates()->all();
})->throws(InvalidConfiguration::class, 'WEZEL_KRAJOWY_IDP_CERTIFICATES');

it('reports unreachable metadata as an ApiException', function (): void {
    Http::fake(['https://int.login.gov.pl/login/metadata' => Http::response('', 503)]);

    WezelKrajowy::identityProviderMetadata(true);
})->throws(ApiException::class, '503');

it('prints the service provider metadata from the console', function (): void {
    $this->artisan('wezel-krajowy:metadata')
        ->expectsOutputToContain('entityID="https://sp.example.pl"')
        ->assertSuccessful();
});

it('shows and saves the login.gov.pl certificates from the console', function (): void {
    Http::fake(['https://int.login.gov.pl/login/metadata' => Http::response(metadataFixture())]);
    $directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wezel-krajowy-idp-' . bin2hex(random_bytes(4));

    try {
        $this->artisan('wezel-krajowy:idp-metadata', ['--save' => $directory])
            ->expectsOutputToContain('https://int.login.gov.pl/login/metadata')
            ->expectsOutputToContain('WEZEL_KRAJOWY_IDP_CERTIFICATES=')
            ->assertSuccessful();

        expect(glob($directory . '/*.pem'))->toHaveCount(2);
    } finally {
        array_map('unlink', glob($directory . '/*') ?: []);
        is_dir($directory) && rmdir($directory);
    }

    Http::assertSent(static fn(Request $request): bool => $request->method() === 'GET' && $request->url() === 'https://int.login.gov.pl/login/metadata');
});

it('adds the ForeignAuthentication field when cross-border login is enabled', function (): void {
    config()->set('wezel-krajowy.authn.foreign_authentication', true);
    reloadService();

    $message = WezelKrajowy::authnRequest('/back', LevelOfAssurance::High);

    expect($message->fields)->toHaveKeys(['SAMLRequest', 'ForeignAuthentication'])
        ->and($message->fields['ForeignAuthentication'])->toBe('true')
        ->and($message->request->levelOfAssurance)->toBe(LevelOfAssurance::High)
        ->and($message->toHtml())->toContain('name="ForeignAuthentication" value="true"');
});
