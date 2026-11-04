<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Saml;

use Beziworld\WezelKrajowy\Data\IdpMetadata;
use Beziworld\WezelKrajowy\Exceptions\ApiException;
use Beziworld\WezelKrajowy\Exceptions\InvalidConfiguration;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Beziworld\WezelKrajowy\Security\Certificate;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;

/**
 * Supplies the certificates trusted to sign login.gov.pl messages.
 *
 * Pinned certificates from the configuration take precedence. Otherwise,
 * when explicitly enabled, the signing certificates are read from the
 * public metadata of the environment over HTTPS and cached.
 */
final class IdentityProviderCertificates
{
    private const string CACHE_KEY = 'wezel-krajowy:idp-metadata:';

    /** @var list<Certificate>|null */
    private ?array $resolved = null;

    public function __construct(
        private readonly WezelKrajowyConfig $config,
        private readonly HttpFactory $http,
        private readonly Repository $cache,
    ) {}

    /**
     * @return list<Certificate>
     *
     * @throws InvalidConfiguration|ApiException
     */
    public function all(): array
    {
        if ($this->resolved !== null) {
            return $this->resolved;
        }

        if ($this->config->idpCertificates !== []) {
            return $this->resolved = array_map(
                static fn(string $source): Certificate => Certificate::load($source, 'idp.certificates'),
                $this->config->idpCertificates,
            );
        }

        if (! $this->config->trustMetadata) {
            throw InvalidConfiguration::missing('idp.certificates', 'WEZEL_KRAJOWY_IDP_CERTIFICATES (or WEZEL_KRAJOWY_TRUST_METADATA=true)');
        }

        $metadata = $this->metadata();

        if ($metadata->signingCertificates === []) {
            throw ApiException::invalidResponse($this->config->metadataUrl(), 'the metadata lists no signing certificate');
        }

        return $this->resolved = array_map(
            static fn(string $der): Certificate => Certificate::load($der, 'idp metadata'),
            $metadata->signingCertificates,
        );
    }

    /**
     * Fetches (or reads from cache) and parses the identity provider metadata.
     *
     * @throws ApiException
     */
    public function metadata(bool $fresh = false): IdpMetadata
    {
        $url = $this->config->metadataUrl();
        $key = self::CACHE_KEY . hash('sha256', $url);
        $cached = $fresh ? null : $this->cache->get($key);

        if (is_string($cached)) {
            try {
                $metadata = Metadata::parseIdp($cached);

                if (! $metadata->isExpired()) {
                    return $metadata;
                }
            } catch (InvalidResponse) {
                $this->cache->forget($key);
            }
        }

        try {
            $response = $this->http->createPendingRequest()
                ->accept('application/samlmetadata+xml, application/xml')
                ->timeout($this->config->timeout)
                ->connectTimeout($this->config->connectTimeout)
                ->retry(2, 500, throw: false)
                ->get($url);
        } catch (ConnectionException $exception) {
            throw ApiException::transport($url, $exception);
        }

        if ($response->failed()) {
            throw ApiException::http($url, $response->status());
        }

        try {
            $metadata = Metadata::parseIdp($response->body());
        } catch (InvalidResponse $exception) {
            throw ApiException::invalidResponse($url, $exception->getMessage());
        }

        if ($this->config->metadataCacheTtl > 0) {
            $this->cache->put($key, $response->body(), $this->config->metadataCacheTtl);
        }

        return $metadata;
    }
}
