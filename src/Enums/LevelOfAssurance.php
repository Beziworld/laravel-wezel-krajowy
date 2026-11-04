<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Enums;

/**
 * eIDAS level of assurance of an electronic identification means.
 *
 * The case values are the AuthnContextClassRef URIs used by login.gov.pl.
 */
enum LevelOfAssurance: string
{
    case Low = 'http://eidas.europa.eu/LoA/low';
    case Substantial = 'http://eidas.europa.eu/LoA/substantial';
    case High = 'http://eidas.europa.eu/LoA/high';

    /**
     * Resolves a level from its URI or short name (low, substantial, high).
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

    public function rank(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Substantial => 2,
            self::High => 3,
        };
    }

    /**
     * Tells whether this level satisfies the given minimum level.
     */
    public function satisfies(self $minimum): bool
    {
        return $this->rank() >= $minimum->rank();
    }

    public function shortName(): string
    {
        return strtolower($this->name);
    }
}
