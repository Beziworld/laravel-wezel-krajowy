<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Exceptions;

/**
 * Raised when an assertion or request identifier has already been consumed,
 * is unknown, has expired or belongs to another browser session.
 */
final class ReplayDetected extends WezelKrajowyException
{
    public static function assertion(string $id): self
    {
        return new self(sprintf('The assertion %s has already been used.', $id));
    }

    public static function unknownRequest(string $id): self
    {
        return new self(sprintf('The response refers to the request %s, which is unknown, expired or already completed.', $id));
    }

    public static function foreignSession(string $id): self
    {
        return new self(sprintf('The request %s was not started in this browser session.', $id));
    }

    public function reason(): string
    {
        return 'replay';
    }
}
