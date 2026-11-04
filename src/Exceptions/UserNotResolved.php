<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Exceptions;

/**
 * Raised when the application identity resolver does not return a user for
 * an otherwise valid login.gov.pl identity.
 */
final class UserNotResolved extends WezelKrajowyException
{
    public static function make(): self
    {
        return new self('No local account matches the identity confirmed by login.gov.pl.');
    }

    public function reason(): string
    {
        return 'user_not_found';
    }
}
