<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Data;

/**
 * Outcome of a single logout request sent to login.gov.pl.
 */
final readonly class LogoutResult
{
    public const string SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    public const string PARTIAL_LOGOUT = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';

    /**
     * @param list<string> $statusCodes Top-level status code first.
     * @param array<string, mixed> $raw
     */
    public function __construct(
        public string $requestId,
        public ?string $responseId,
        public array $statusCodes,
        public ?string $statusMessage = null,
        public array $raw = [],
    ) {}

    public function status(): string
    {
        return $this->statusCodes[0] ?? '';
    }

    /**
     * Logout completed at login.gov.pl and at the identity provider.
     */
    public function successful(): bool
    {
        return $this->status() === self::SUCCESS && ! $this->partial();
    }

    /**
     * The identity provider session could not be closed.
     */
    public function partial(): bool
    {
        return in_array(self::PARTIAL_LOGOUT, $this->statusCodes, true);
    }
}
