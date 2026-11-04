<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Security;

use Beziworld\WezelKrajowy\Exceptions\InvalidConfiguration;

/**
 * Reads key and certificate settings that hold either a file path or the
 * material itself.
 */
final class KeyMaterial
{
    /**
     * @throws InvalidConfiguration
     */
    public static function read(string $source, string $configKey): string
    {
        $source = trim($source);

        if ($source === '') {
            throw InvalidConfiguration::invalid($configKey, 'the key setting', 'empty value');
        }

        if (str_contains($source, '-----BEGIN')) {
            return $source;
        }

        if (strlen($source) < 4096 && ! str_contains($source, "\n") && is_file($source)) {
            $content = file_get_contents($source);

            if ($content === false || trim($content) === '') {
                throw InvalidConfiguration::invalid($configKey, 'the key setting', 'file is empty or unreadable');
            }

            return $content;
        }

        if (base64_decode($source, true) !== false && strlen($source) > 64) {
            return $source;
        }

        throw InvalidConfiguration::invalid($configKey, 'the key setting', sprintf('file "%s" does not exist', $source));
    }
}
