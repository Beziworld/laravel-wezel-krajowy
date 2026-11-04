<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Security;

/**
 * Concatenation key derivation function (NIST SP 800-56A, XML Encryption 1.1 ConcatKDF).
 *
 * login.gov.pl encodes AlgorithmID, PartyUInfo and PartyVInfo as hex of
 * "Datalen || Data" and expects the whole decoded values, including the
 * four-byte length prefixes, to be concatenated into OtherInfo.
 */
final class ConcatKdf
{
    public static function derive(string $sharedSecret, string $otherInfo, int $length, string $hash = 'sha256'): string
    {
        $output = '';
        $counter = 1;

        while (strlen($output) < $length) {
            $output .= hash($hash, pack('N', $counter) . $sharedSecret . $otherInfo, true);
            $counter++;
        }

        return substr($output, 0, $length);
    }

    /**
     * Decodes a ConcatKDFParams hex attribute; returns null for invalid hex.
     */
    public static function decodeParameter(string $hex): ?string
    {
        $hex = trim($hex);

        if ($hex === '') {
            return '';
        }

        if (strlen($hex) % 2 !== 0 || ! ctype_xdigit($hex)) {
            return null;
        }

        $decoded = hex2bin($hex);

        return $decoded === false ? null : $decoded;
    }

    /**
     * Encodes a value as the "Datalen || Data" hex form used by login.gov.pl.
     */
    public static function encodeParameter(string $value): string
    {
        return strtoupper(bin2hex(pack('N', strlen($value)) . $value));
    }
}
