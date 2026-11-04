<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Support;

/**
 * PESEL (Polish national identification number) helpers.
 */
final class Pesel
{
    private const array WEIGHTS = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];

    public static function isValid(string $pesel): bool
    {
        if (preg_match('/^\d{11}$/', $pesel) !== 1) {
            return false;
        }

        $sum = 0;

        foreach (self::WEIGHTS as $index => $weight) {
            $sum += $weight * (int) $pesel[$index];
        }

        return (10 - $sum % 10) % 10 === (int) $pesel[10];
    }

    /**
     * Extracts a PESEL from an eIDAS PersonIdentifier.
     *
     * login.gov.pl sends the bare number for Polish identities; the eIDAS
     * "PL/PL/<number>" form is accepted as well. Foreign identifiers and
     * numbers with an invalid checksum yield null.
     */
    public static function fromPersonIdentifier(string $identifier): ?string
    {
        $value = trim($identifier);

        if (preg_match('#^PL/[A-Z]{2}/(\d{11})$#i', $value, $match) === 1) {
            $value = $match[1];
        }

        return self::isValid($value) ? $value : null;
    }
}
