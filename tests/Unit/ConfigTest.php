<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Enums\Environment;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Enums\NameIdFormat;
use Beziworld\WezelKrajowy\Enums\SpType;
use Beziworld\WezelKrajowy\Exceptions\InvalidConfiguration;
use Beziworld\WezelKrajowy\Security\KeyPair;
use Beziworld\WezelKrajowy\Tests\Support\Keys;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;

function minimalConfig(array $overrides = []): array
{
    return array_replace_recursive([
        'sp' => ['entity_id' => 'https://sp.example.pl', 'signing' => ['key' => 'a'], 'encryption' => ['key' => 'b']],
    ], $overrides);
}

it('requires the issuer and both keys', function (array $config, string $message): void {
    expect(fn() => WezelKrajowyConfig::fromArray($config))->toThrow(InvalidConfiguration::class, $message);
})->with([
    'issuer' => [['sp' => ['signing' => ['key' => 'a'], 'encryption' => ['key' => 'b']]], 'WEZEL_KRAJOWY_ISSUER'],
    'signing key' => [['sp' => ['entity_id' => 'x', 'encryption' => ['key' => 'b']]], 'WEZEL_KRAJOWY_SIGNING_KEY'],
    'encryption key' => [['sp' => ['entity_id' => 'x', 'signing' => ['key' => 'a']]], 'WEZEL_KRAJOWY_ENCRYPTION_KEY'],
]);

it('rejects unknown enumerated values', function (array $overrides, string $env): void {
    expect(fn() => WezelKrajowyConfig::fromArray(minimalConfig($overrides)))->toThrow(InvalidConfiguration::class, $env);
})->with([
    'environment' => [['environment' => 'staging'], 'WEZEL_KRAJOWY_ENV'],
    'sp type' => [['sp' => ['type' => 'commercial']], 'WEZEL_KRAJOWY_SP_TYPE'],
    'loa' => [['authn' => ['level_of_assurance' => 'medium']], 'WEZEL_KRAJOWY_LOA'],
    'name id' => [['authn' => ['name_id_format' => 'email']], 'WEZEL_KRAJOWY_NAME_ID_FORMAT'],
    'attribute' => [['authn' => ['attributes' => ['ShoeSize']]], 'authn.attributes'],
    'url' => [['idp' => ['sso_url' => 'not a url']], 'WEZEL_KRAJOWY_SSO_URL'],
]);

it('derives the endpoints from the environment and honours overrides', function (): void {
    $production = WezelKrajowyConfig::fromArray(minimalConfig(['environment' => 'production']));
    $private = WezelKrajowyConfig::fromArray(minimalConfig([
        'environment' => 'production-private',
        'idp' => ['artifact_resolution_url' => 'https://simulator.example/ars'],
    ]));

    expect($production->ssoUrl())->toBe('https://login.gov.pl/login/SingleSignOnService')
        ->and($production->singleLogoutUrl())->toBe('https://login.gov.pl/login-services/singleLogoutService')
        ->and($production->metadataUrl())->toBe('https://login.gov.pl/login/metadata')
        ->and($private->environment)->toBe(Environment::ProductionPrivate)
        ->and($private->ssoUrl())->toBe('https://podmiotyzewnetrzne.login.gov.pl/login/SingleSignOnService')
        ->and($private->artifactResolutionUrl())->toBe('https://simulator.example/ars');
});

it('applies documented defaults', function (): void {
    $config = WezelKrajowyConfig::fromArray(minimalConfig(['idp' => ['certificates' => 'a.pem, b.pem']]));

    expect($config->environment)->toBe(Environment::Integration)
        ->and($config->spType)->toBe(SpType::Public)
        ->and($config->levelOfAssurance)->toBe(LevelOfAssurance::Substantial)
        ->and($config->nameIdFormat)->toBe(NameIdFormat::Unspecified)
        ->and($config->idpCertificates)->toBe(['a.pem', 'b.pem'])
        ->and($config->clockSkew)->toBe(120)
        ->and($config->requireSignedResponse)->toBeTrue()
        ->and($config->bindToSession)->toBeTrue();
});

it('loads keys and certificates from files', function (): void {
    $directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wezel-krajowy-' . bin2hex(random_bytes(4));
    mkdir($directory);
    file_put_contents($directory . '/key.pem', Keys::pem('sp-signing')['key']);
    file_put_contents($directory . '/cert.pem', Keys::pem('sp-signing')['certificate']);

    try {
        $pair = KeyPair::load($directory . '/key.pem', $directory . '/cert.pem', null, 'sp.signing');

        expect($pair->isEc())->toBeTrue()
            ->and($pair->curve())->toBe('secp256r1')
            ->and($pair->certificate()?->fingerprint())->toBe(Keys::certificate('sp-signing')->fingerprint());
    } finally {
        array_map('unlink', glob($directory . '/*') ?: []);
        rmdir($directory);
    }

    expect(fn() => KeyPair::load($directory . '/missing.pem', null, null, 'sp.signing'))->toThrow(InvalidConfiguration::class, 'does not exist');
});
