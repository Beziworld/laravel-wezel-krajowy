<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Exceptions;

/**
 * Raised when an XML signature is missing, malformed, uses a forbidden
 * algorithm or does not verify against a trusted certificate.
 */
final class InvalidSignature extends WezelKrajowyException
{
    public static function because(string $element, string $detail): self
    {
        return new self(sprintf('The signature of <%s> is not valid: %s.', $element, $detail));
    }

    public function reason(): string
    {
        return 'invalid_signature';
    }
}
