<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Exceptions;

/**
 * Raised when a SAML message is malformed or fails a protocol check
 * (InResponseTo, audience, recipient, validity window, level of assurance).
 */
final class InvalidResponse extends WezelKrajowyException
{
    public static function because(string $detail): self
    {
        return new self('The login.gov.pl response was rejected: ' . $detail . '.');
    }

    public function reason(): string
    {
        return 'invalid_response';
    }
}
