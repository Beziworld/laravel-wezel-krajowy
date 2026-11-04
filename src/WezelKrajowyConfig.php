<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy;

use Beziworld\WezelKrajowy\Enums\EidasAttribute;
use Beziworld\WezelKrajowy\Enums\Environment;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Enums\NameIdFormat;
use Beziworld\WezelKrajowy\Enums\SpType;
use Beziworld\WezelKrajowy\Exceptions\InvalidConfiguration;

/**
 * Validated, immutable view of the "wezel-krajowy" configuration file.
 */
final readonly class WezelKrajowyConfig
{
    /**
     * @param list<string> $idpCertificates
     * @param list<EidasAttribute> $attributes Optional attributes requested on top of the mandatory set.
     */
    public function __construct(
        public string $entityId,
        public string $signingKey,
        public string $encryptionKey,
        public Environment $environment = Environment::Integration,
        public ?string $providerName = null,
        public SpType $spType = SpType::Public,
        public ?string $acsUrl = null,
        public ?string $signingCertificate = null,
        public ?string $signingPassphrase = null,
        public ?string $encryptionCertificate = null,
        public ?string $encryptionPassphrase = null,
        public ?string $idpEntityId = null,
        public array $idpCertificates = [],
        public bool $trustMetadata = false,
        public ?string $metadataUrlOverride = null,
        public int $metadataCacheTtl = 3600,
        public ?string $ssoUrlOverride = null,
        public ?string $artifactResolutionUrlOverride = null,
        public ?string $singleLogoutUrlOverride = null,
        public LevelOfAssurance $levelOfAssurance = LevelOfAssurance::Substantial,
        public NameIdFormat $nameIdFormat = NameIdFormat::Unspecified,
        public array $attributes = [],
        public bool $foreignAuthentication = false,
        public int $clockSkew = 120,
        public int $requestTtl = 900,
        public bool $requireSignedResponse = true,
        public bool $bindToSession = true,
        public ?string $cacheStore = null,
        public int $timeout = 30,
        public int $connectTimeout = 10,
    ) {}

    /**
     * @param array<string, mixed> $config
     *
     * @throws InvalidConfiguration
     */
    public static function fromArray(array $config): self
    {
        $sp = self::section($config, 'sp');
        $signing = self::section($sp, 'signing');
        $encryption = self::section($sp, 'encryption');
        $idp = self::section($config, 'idp');
        $authn = self::section($config, 'authn');
        $security = self::section($config, 'security');
        $http = self::section($config, 'http');

        $environmentValue = self::string($config['environment'] ?? null) ?? Environment::Integration->value;
        $environment = Environment::tryFrom(strtolower($environmentValue))
            ?? throw InvalidConfiguration::invalid('environment', 'WEZEL_KRAJOWY_ENV', 'expected integration, production or production-private');

        $spTypeValue = self::string($sp['type'] ?? null) ?? SpType::Public->value;
        $spType = SpType::tryFrom(strtolower($spTypeValue))
            ?? throw InvalidConfiguration::invalid('sp.type', 'WEZEL_KRAJOWY_SP_TYPE', 'expected public or private');

        $loaValue = self::string($authn['level_of_assurance'] ?? null) ?? 'substantial';
        $loa = LevelOfAssurance::fromName($loaValue)
            ?? throw InvalidConfiguration::invalid('authn.level_of_assurance', 'WEZEL_KRAJOWY_LOA', 'expected low, substantial or high');

        $formatValue = self::string($authn['name_id_format'] ?? null) ?? 'unspecified';
        $format = NameIdFormat::fromName($formatValue)
            ?? throw InvalidConfiguration::invalid('authn.name_id_format', 'WEZEL_KRAJOWY_NAME_ID_FORMAT', 'expected unspecified, persistent or transient');

        $acsUrl = self::url($sp['acs_url'] ?? null, 'sp.acs_url', 'WEZEL_KRAJOWY_ACS_URL');

        return new self(
            entityId: self::string($sp['entity_id'] ?? null) ?? throw InvalidConfiguration::missing('sp.entity_id', 'WEZEL_KRAJOWY_ISSUER'),
            signingKey: self::string($signing['key'] ?? null) ?? throw InvalidConfiguration::missing('sp.signing.key', 'WEZEL_KRAJOWY_SIGNING_KEY'),
            encryptionKey: self::string($encryption['key'] ?? null) ?? throw InvalidConfiguration::missing('sp.encryption.key', 'WEZEL_KRAJOWY_ENCRYPTION_KEY'),
            environment: $environment,
            providerName: self::string($sp['provider_name'] ?? null),
            spType: $spType,
            acsUrl: $acsUrl,
            signingCertificate: self::string($signing['certificate'] ?? null),
            signingPassphrase: self::string($signing['passphrase'] ?? null),
            encryptionCertificate: self::string($encryption['certificate'] ?? null),
            encryptionPassphrase: self::string($encryption['passphrase'] ?? null),
            idpEntityId: self::string($idp['entity_id'] ?? null),
            idpCertificates: self::list($idp['certificates'] ?? []),
            trustMetadata: filter_var($idp['trust_metadata'] ?? false, FILTER_VALIDATE_BOOL),
            metadataUrlOverride: self::url($idp['metadata_url'] ?? null, 'idp.metadata_url', 'WEZEL_KRAJOWY_METADATA_URL'),
            metadataCacheTtl: self::integer($idp['metadata_cache_ttl'] ?? null, 3600, 0),
            ssoUrlOverride: self::url($idp['sso_url'] ?? null, 'idp.sso_url', 'WEZEL_KRAJOWY_SSO_URL'),
            artifactResolutionUrlOverride: self::url($idp['artifact_resolution_url'] ?? null, 'idp.artifact_resolution_url', 'WEZEL_KRAJOWY_ARTIFACT_RESOLUTION_URL'),
            singleLogoutUrlOverride: self::url($idp['slo_url'] ?? null, 'idp.slo_url', 'WEZEL_KRAJOWY_SLO_URL'),
            levelOfAssurance: $loa,
            nameIdFormat: $format,
            attributes: self::attributes($authn['attributes'] ?? []),
            foreignAuthentication: filter_var($authn['foreign_authentication'] ?? false, FILTER_VALIDATE_BOOL),
            clockSkew: self::integer($security['clock_skew'] ?? null, 120, 0),
            requestTtl: self::integer($security['request_ttl'] ?? null, 900, 60),
            requireSignedResponse: filter_var($security['require_signed_response'] ?? true, FILTER_VALIDATE_BOOL),
            bindToSession: filter_var($security['bind_to_session'] ?? true, FILTER_VALIDATE_BOOL),
            cacheStore: self::string($security['cache_store'] ?? null),
            timeout: self::integer($http['timeout'] ?? null, 30, 1),
            connectTimeout: self::integer($http['connect_timeout'] ?? null, 10, 1),
        );
    }

    public function ssoUrl(): string
    {
        return $this->ssoUrlOverride ?? $this->environment->ssoUrl();
    }

    public function artifactResolutionUrl(): string
    {
        return $this->artifactResolutionUrlOverride ?? $this->environment->artifactResolutionUrl();
    }

    public function singleLogoutUrl(): string
    {
        return $this->singleLogoutUrlOverride ?? $this->environment->singleLogoutUrl();
    }

    public function metadataUrl(): string
    {
        return $this->metadataUrlOverride ?? $this->environment->metadataUrl();
    }

    /**
     * Mandatory attributes followed by the configured optional ones.
     *
     * @return list<EidasAttribute>
     */
    public function requestedAttributes(): array
    {
        $attributes = EidasAttribute::mandatory();

        foreach ($this->attributes as $attribute) {
            if (! in_array($attribute, $attributes, true)) {
                $attributes[] = $attribute;
            }
        }

        return $attributes;
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private static function section(array $config, string $key): array
    {
        $value = $config[$key] ?? [];

        if (! is_array($value)) {
            return [];
        }

        $section = [];

        foreach ($value as $name => $item) {
            $section[(string) $name] = $item;
        }

        return $section;
    }

    private static function string(mixed $value): ?string
    {
        return is_scalar($value) && trim((string) $value) !== '' ? trim((string) $value) : null;
    }

    private static function integer(mixed $value, int $default, int $min): int
    {
        return is_numeric($value) && (int) $value >= $min ? (int) $value : $default;
    }

    private static function url(mixed $value, string $key, string $env): ?string
    {
        $url = self::string($value);

        if ($url !== null && filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw InvalidConfiguration::invalid($key, $env, 'not a valid URL');
        }

        return $url;
    }

    /**
     * @return list<string>
     */
    private static function list(mixed $value): array
    {
        if (is_string($value)) {
            $value = str_contains($value, '-----BEGIN') ? [$value] : explode(',', $value);
        }

        if (! is_array($value)) {
            return [];
        }

        $items = [];

        foreach ($value as $item) {
            $string = self::string($item);

            if ($string !== null) {
                $items[] = $string;
            }
        }

        return $items;
    }

    /**
     * @return list<EidasAttribute>
     */
    private static function attributes(mixed $value): array
    {
        $attributes = [];

        foreach (self::list($value) as $name) {
            $attribute = EidasAttribute::fromFriendlyName($name)
                ?? throw InvalidConfiguration::invalid('authn.attributes', 'the authn.attributes setting', sprintf('unknown eIDAS attribute "%s"', $name));

            if (! $attribute->isMandatory()) {
                $attributes[] = $attribute;
            }
        }

        return $attributes;
    }
}
