<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Exceptions;

/**
 * Raised when an encrypted assertion cannot be decrypted with the configured key.
 */
final class DecryptionFailed extends WezelKrajowyException
{
    public static function because(string $detail): self
    {
        return new self('The encrypted assertion could not be decrypted: ' . $detail . '.');
    }

    public function reason(): string
    {
        return 'decryption';
    }
}
