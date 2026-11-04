<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Enums;

/**
 * NameID formats accepted by login.gov.pl in NameIDPolicy.
 */
enum NameIdFormat: string
{
    case Unspecified = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
    case Persistent = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    case Transient = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

    /**
     * Resolves a format from its URN or short name (unspecified, persistent, transient).
     */
    public static function fromName(string $value): ?self
    {
        $normalized = strtolower(trim($value));

        foreach (self::cases() as $case) {
            if ($case->value === trim($value) || strtolower($case->name) === $normalized) {
                return $case;
            }
        }

        return null;
    }
}
