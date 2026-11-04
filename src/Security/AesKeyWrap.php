<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Security;

use InvalidArgumentException;

/**
 * AES Key Wrap (RFC 3394), used by XML Encryption kw-aes128/192/256.
 */
final class AesKeyWrap
{
    private const string DEFAULT_IV = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";

    public static function wrap(string $kek, string $key): string
    {
        self::assertSizes($kek, $key);

        $a = self::DEFAULT_IV;
        $r = str_split($key, 8);
        $n = count($r);

        for ($j = 0; $j <= 5; $j++) {
            for ($i = 0; $i < $n; $i++) {
                $b = self::encryptBlock($kek, $a . $r[$i]);
                $a = substr($b, 0, 8) ^ pack('J', $n * $j + $i + 1);
                $r[$i] = substr($b, 8);
            }
        }

        return $a . implode('', $r);
    }

    /**
     * Unwraps a key; returns null when the integrity check fails.
     */
    public static function unwrap(string $kek, string $wrapped): ?string
    {
        if (strlen($wrapped) < 24 || strlen($wrapped) % 8 !== 0 || ! in_array(strlen($kek), [16, 24, 32], true)) {
            return null;
        }

        $a = substr($wrapped, 0, 8);
        $r = str_split(substr($wrapped, 8), 8);
        $n = count($r);

        for ($j = 5; $j >= 0; $j--) {
            for ($i = $n - 1; $i >= 0; $i--) {
                $b = self::decryptBlock($kek, ($a ^ pack('J', $n * $j + $i + 1)) . $r[$i]);
                $a = substr($b, 0, 8);
                $r[$i] = substr($b, 8);
            }
        }

        return hash_equals(self::DEFAULT_IV, $a) ? implode('', $r) : null;
    }

    private static function assertSizes(string $kek, string $key): void
    {
        if (! in_array(strlen($kek), [16, 24, 32], true) || strlen($key) < 16 || strlen($key) % 8 !== 0) {
            throw new InvalidArgumentException('Invalid key sizes for AES key wrap.');
        }
    }

    private static function encryptBlock(string $kek, string $block): string
    {
        return (string) openssl_encrypt($block, self::cipher($kek), $kek, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    }

    private static function decryptBlock(string $kek, string $block): string
    {
        return (string) openssl_decrypt($block, self::cipher($kek), $kek, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    }

    private static function cipher(string $kek): string
    {
        return 'aes-' . (strlen($kek) * 8) . '-ecb';
    }
}
