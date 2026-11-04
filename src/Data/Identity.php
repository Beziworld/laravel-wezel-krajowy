<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Data;

use Beziworld\WezelKrajowy\Enums\EidasAttribute;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Carbon\CarbonImmutable;

/**
 * Natural person identity confirmed by login.gov.pl.
 */
final readonly class Identity
{
    public const string TIMEZONE = 'Europe/Warsaw';

    /**
     * @param array<string, list<string>> $attributes All attribute values keyed by FriendlyName (or Name when no FriendlyName is given).
     * @param array<string, mixed> $raw
     */
    public function __construct(
        public string $firstName,
        public string $familyName,
        public CarbonImmutable $dateOfBirth,
        public string $personIdentifier,
        public ?string $pesel,
        public LevelOfAssurance $levelOfAssurance,
        public ?string $identityProvider,
        public string $nameId,
        public ?string $nameIdFormat,
        public ?string $sessionIndex,
        public string $assertionId,
        public CarbonImmutable $authenticatedAt,
        public array $attributes = [],
        public array $raw = [],
    ) {}

    /**
     * Restores an identity serialized with toArray().
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $string = static fn(string $key): string => is_scalar($data[$key] ?? null) ? (string) $data[$key] : '';
        $nullable = static fn(string $key): ?string => is_scalar($data[$key] ?? null) && (string) $data[$key] !== '' ? (string) $data[$key] : null;
        $attributes = [];

        foreach (is_array($data['attributes'] ?? null) ? $data['attributes'] : [] as $name => $values) {
            if (is_string($name) && is_array($values)) {
                $attributes[$name] = array_values(array_map(static fn(mixed $value): string => is_scalar($value) ? (string) $value : '', $values));
            }
        }

        return new self(
            firstName: $string('first_name'),
            familyName: $string('family_name'),
            dateOfBirth: CarbonImmutable::parse($string('date_of_birth'), self::TIMEZONE)->startOfDay(),
            personIdentifier: $string('person_identifier'),
            pesel: $nullable('pesel'),
            levelOfAssurance: LevelOfAssurance::fromName($string('level_of_assurance')) ?? LevelOfAssurance::Low,
            identityProvider: $nullable('identity_provider'),
            nameId: $string('name_id'),
            nameIdFormat: $nullable('name_id_format'),
            sessionIndex: $nullable('session_index'),
            assertionId: $string('assertion_id'),
            authenticatedAt: CarbonImmutable::parse($string('authenticated_at'))->setTimezone('UTC'),
            attributes: $attributes,
            raw: is_array($data['raw'] ?? null) ? $data['raw'] : [],
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'first_name' => $this->firstName,
            'family_name' => $this->familyName,
            'date_of_birth' => $this->dateOfBirth->toDateString(),
            'person_identifier' => $this->personIdentifier,
            'pesel' => $this->pesel,
            'level_of_assurance' => $this->levelOfAssurance->value,
            'identity_provider' => $this->identityProvider,
            'name_id' => $this->nameId,
            'name_id_format' => $this->nameIdFormat,
            'session_index' => $this->sessionIndex,
            'assertion_id' => $this->assertionId,
            'authenticated_at' => $this->authenticatedAt->toIso8601ZuluString('millisecond'),
            'attributes' => $this->attributes,
            'raw' => $this->raw,
        ];
    }

    public function fullName(): string
    {
        return trim($this->firstName . ' ' . $this->familyName);
    }

    /**
     * First value of an attribute by FriendlyName, Name URI or enum case.
     */
    public function attribute(EidasAttribute|string $name): ?string
    {
        $key = $name instanceof EidasAttribute ? $name->name : $name;

        if (isset($this->attributes[$key][0])) {
            return $this->attributes[$key][0];
        }

        $case = $name instanceof EidasAttribute ? $name : EidasAttribute::fromFriendlyName($name);

        return $case !== null ? ($this->attributes[$case->name][0] ?? $this->attributes[$case->value][0] ?? null) : null;
    }

    /**
     * Tells whether the person identifier is a Polish PESEL number.
     */
    public function hasPesel(): bool
    {
        return $this->pesel !== null;
    }

    public function satisfies(LevelOfAssurance $minimum): bool
    {
        return $this->levelOfAssurance->satisfies($minimum);
    }
}
