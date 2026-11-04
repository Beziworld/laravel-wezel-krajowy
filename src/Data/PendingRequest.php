<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Data;

use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Carbon\CarbonImmutable;

/**
 * AuthnRequest that was sent to login.gov.pl and awaits its response.
 */
final readonly class PendingRequest
{
    public function __construct(
        public string $id,
        public LevelOfAssurance $levelOfAssurance,
        public string $acsUrl,
        public CarbonImmutable $issuedAt,
        public ?string $returnTo = null,
    ) {}

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): ?self
    {
        $id = $data['id'] ?? null;
        $loa = is_string($data['loa'] ?? null) ? LevelOfAssurance::tryFrom($data['loa']) : null;
        $acs = $data['acs_url'] ?? null;
        $issued = $data['issued_at'] ?? null;
        $returnTo = $data['return_to'] ?? null;

        if (! is_string($id) || $loa === null || ! is_string($acs) || ! is_string($issued)) {
            return null;
        }

        return new self($id, $loa, $acs, CarbonImmutable::parse($issued)->setTimezone('UTC'), is_string($returnTo) ? $returnTo : null);
    }

    /**
     * @return array<string, string|null>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'loa' => $this->levelOfAssurance->value,
            'acs_url' => $this->acsUrl,
            'issued_at' => $this->issuedAt->toIso8601ZuluString('millisecond'),
            'return_to' => $this->returnTo,
        ];
    }
}
