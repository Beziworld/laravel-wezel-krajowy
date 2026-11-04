<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Saml;

use Beziworld\WezelKrajowy\Data\PendingRequest;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Cache\Repository;

/**
 * Cache-backed registry of pending AuthnRequests and consumed assertions.
 *
 * The browser returns from login.gov.pl with a cross-site POST that carries
 * no SameSite=Lax session cookie, so pending requests are kept in the cache
 * rather than only in the session. Each request can be completed once.
 */
final class RequestStore
{
    private const string PREFIX = 'wezel-krajowy:';

    public function __construct(
        private readonly Repository $cache,
        private readonly int $ttl,
    ) {}

    public function put(PendingRequest $request): void
    {
        $this->cache->put(self::PREFIX . 'request:' . $request->id, $request->toArray(), $this->ttl);
    }

    /**
     * Removes and returns a pending request; null when unknown or expired.
     */
    public function pull(string $id): ?PendingRequest
    {
        $data = $this->cache->pull(self::PREFIX . 'request:' . $id);

        if (! is_array($data)) {
            return null;
        }

        $request = PendingRequest::fromArray($data);

        if ($request === null || $request->issuedAt->addSeconds($this->ttl)->isPast()) {
            return null;
        }

        return $request;
    }

    /**
     * Records an assertion ID until it expires; false when it was already recorded.
     */
    public function consumeAssertion(string $id, CarbonImmutable $until): bool
    {
        $seconds = max(60, (int) ceil(CarbonImmutable::now()->diffInSeconds($until, false)) + 60);

        return $this->cache->add(self::PREFIX . 'assertion:' . hash('sha256', $id), true, $seconds);
    }
}
