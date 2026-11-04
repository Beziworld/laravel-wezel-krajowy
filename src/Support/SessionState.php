<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Support;

use Beziworld\WezelKrajowy\Data\Identity;
use Illuminate\Contracts\Session\Session;
use Throwable;

/**
 * Session keys used by the package.
 *
 * The session remembers which AuthnRequests were started in this browser
 * (to bind responses to the session) and the identity of the last
 * successful login (for single logout and level of assurance checks).
 */
final class SessionState
{
    public const string PENDING = 'wezel_krajowy.pending';

    public const string IDENTITY = 'wezel_krajowy.identity';

    private const int MAX_PENDING = 10;

    public static function rememberRequest(Session $session, string $id): void
    {
        $pending = self::pending($session);
        $pending[] = $id;
        $session->put(self::PENDING, array_slice(array_values(array_unique($pending)), -self::MAX_PENDING));
    }

    /**
     * Removes a request ID from the session; false when it was not there.
     */
    public static function forgetRequest(Session $session, string $id): bool
    {
        $pending = self::pending($session);

        if (! in_array($id, $pending, true)) {
            return false;
        }

        $session->put(self::PENDING, array_values(array_filter($pending, static fn(string $item): bool => $item !== $id)));

        return true;
    }

    public static function storeIdentity(Session $session, Identity $identity): void
    {
        $session->put(self::IDENTITY, $identity->toArray());
    }

    public static function identity(Session $session): ?Identity
    {
        $data = $session->get(self::IDENTITY);

        if (! is_array($data)) {
            return null;
        }

        try {
            $normalized = [];

            foreach ($data as $key => $value) {
                $normalized[(string) $key] = $value;
            }

            return Identity::fromArray($normalized);
        } catch (Throwable) {
            return null;
        }
    }

    public static function forgetIdentity(Session $session): void
    {
        $session->forget(self::IDENTITY);
    }

    /**
     * @return list<string>
     */
    private static function pending(Session $session): array
    {
        $value = $session->get(self::PENDING, []);

        return is_array($value) ? array_values(array_filter($value, 'is_string')) : [];
    }
}
