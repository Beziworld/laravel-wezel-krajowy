<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Tests;

use Beziworld\WezelKrajowy\Tests\Support\FakeLoginGovPl;
use Beziworld\WezelKrajowy\Tests\Support\Keys;
use Beziworld\WezelKrajowy\WezelKrajowyServiceProvider;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    public const string ARTIFACT_URL = 'https://int.login.gov.pl/login-services/idpArtifactResolutionService';

    public const string SLO_URL = 'https://int.login.gov.pl/login-services/singleLogoutService';

    public const string SSO_URL = 'https://int.login.gov.pl/login/SingleSignOnService';

    protected function setUp(): void
    {
        parent::setUp();

        Http::preventStrayRequests();
    }

    protected function getPackageProviders($app): array
    {
        return [WezelKrajowyServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:' . base64_encode(str_repeat('k', 32)));
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('wezel-krajowy.environment', 'integration');
        $app['config']->set('wezel-krajowy.sp.entity_id', FakeLoginGovPl::ENTITY_ID);
        $app['config']->set('wezel-krajowy.sp.provider_name', 'Beziworld Test');
        $app['config']->set('wezel-krajowy.sp.signing.key', Keys::pem('sp-signing')['key']);
        $app['config']->set('wezel-krajowy.sp.signing.certificate', Keys::pem('sp-signing')['certificate']);
        $app['config']->set('wezel-krajowy.sp.encryption.key', Keys::pem('sp-encryption')['key']);
        $app['config']->set('wezel-krajowy.sp.encryption.certificate', Keys::pem('sp-encryption')['certificate']);
        $app['config']->set('wezel-krajowy.idp.certificates', [Keys::pem('idp')['certificate']]);
        $app['config']->set('wezel-krajowy.auth.redirect', '/dashboard');
        $app['config']->set('wezel-krajowy.auth.failure_redirect', '/login');
    }
}
