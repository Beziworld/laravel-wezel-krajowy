<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Enums;

/**
 * Deployments of the National Electronic Identification Node.
 */
enum Environment: string
{
    /** COI integration (test) environment. */
    case Integration = 'integration';

    /** Production environment for public entities. */
    case Production = 'production';

    /** Production environment for private (commercial) entities. */
    case ProductionPrivate = 'production-private';

    public function baseUrl(): string
    {
        return match ($this) {
            self::Integration => 'https://int.login.gov.pl',
            self::Production => 'https://login.gov.pl',
            self::ProductionPrivate => 'https://podmiotyzewnetrzne.login.gov.pl',
        };
    }

    public function ssoUrl(): string
    {
        return $this->baseUrl() . '/login/SingleSignOnService';
    }

    public function artifactResolutionUrl(): string
    {
        return $this->baseUrl() . '/login-services/idpArtifactResolutionService';
    }

    public function singleLogoutUrl(): string
    {
        return $this->baseUrl() . '/login-services/singleLogoutService';
    }

    public function metadataUrl(): string
    {
        return $this->baseUrl() . '/login/metadata';
    }
}
