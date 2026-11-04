<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Data;

use Carbon\CarbonImmutable;

/**
 * Relevant parts of the login.gov.pl identity provider metadata.
 */
final readonly class IdpMetadata
{
    /**
     * @param list<string> $signingCertificates Base64 DER certificates from KeyDescriptor use="signing".
     * @param list<string> $nameIdFormats
     * @param array<string, string> $attributes FriendlyName to Name URI.
     * @param list<string> $signingMethods
     */
    public function __construct(
        public string $entityId,
        public ?CarbonImmutable $validUntil,
        public ?string $ssoUrl,
        public ?string $artifactResolutionUrl,
        public ?string $singleLogoutUrl,
        public array $signingCertificates,
        public array $nameIdFormats = [],
        public array $attributes = [],
        public array $signingMethods = [],
        public ?string $spType = null,
    ) {}

    public function isExpired(?CarbonImmutable $now = null): bool
    {
        return $this->validUntil !== null && $this->validUntil->lessThan($now ?? CarbonImmutable::now());
    }
}
