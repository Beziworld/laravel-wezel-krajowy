<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Exceptions;

/**
 * Raised when login.gov.pl answers with a non-success SAML status, for
 * example when the identity provider rejected the credentials, access was
 * denied, or the AuthnRequest failed validation.
 */
final class AuthenticationRejected extends WezelKrajowyException
{
    public const string AUTHN_FAILED = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed';

    public const string REQUEST_DENIED = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied';

    public const string REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';

    public const string RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';

    /**
     * Validation error codes documented in the service provider integration guide.
     *
     * @var array<int, string>
     */
    public const array ERROR_CODES = [
        '1000' => 'AuthnContextClassRef has a value other than low, substantial or high',
        '1002' => 'more than one AuthnContextClassRef element',
        '1004' => 'missing AuthnContextClassRef element',
        '1010' => 'missing Extensions element',
        '2002' => 'IsPassive="true" is not allowed',
        '2003' => 'AssertionConsumerServiceIndex is not allowed',
        '2100' => 'Scoping/ProxyCount is not allowed',
        '2101' => 'invalid Extensions/OperationContext element',
        '2102' => 'Scoping without IDPList',
        '2103' => 'IDPList without IDPEntry',
        '2104' => 'more than one IDPEntry',
        '2105' => 'Scoping element is not allowed',
        '2110' => 'Extensions/OperationContext is not allowed',
        '2200' => 'NameIDPolicy Format is not allowed',
        '3000' => 'requested attribute is not allowed',
        '3001' => 'a mandatory attribute is not requested',
        '3002' => 'missing SPType element',
        '3003' => 'SPType value is not allowed',
        '3004' => 'a mandatory attribute is not requested with isRequired="true"',
    ];

    /**
     * @param list<string> $statusCodes Top-level status code first, nested codes after it.
     */
    public function __construct(
        public readonly array $statusCodes,
        public readonly ?string $statusMessage = null,
    ) {
        parent::__construct(sprintf(
            'login.gov.pl rejected the authentication with status %s%s.',
            implode(' / ', array_map(static fn(string $code): string => self::shortCode($code), $statusCodes)),
            $statusMessage !== null && $statusMessage !== '' ? ': ' . $statusMessage : '',
        ));
    }

    /**
     * Numeric validation code found in the status message, when present.
     */
    public function errorCode(): ?string
    {
        if ($this->statusMessage !== null && preg_match('/\b([123]\d{3})\b/', $this->statusMessage, $match) === 1) {
            return $match[1];
        }

        return null;
    }

    public function errorDescription(): ?string
    {
        $code = $this->errorCode();

        return $code !== null ? (self::ERROR_CODES[(int) $code] ?? null) : null;
    }

    public function isAuthnFailed(): bool
    {
        return $this->hasStatus(self::AUTHN_FAILED);
    }

    public function isRequestDenied(): bool
    {
        return $this->hasStatus(self::REQUEST_DENIED);
    }

    /**
     * Tells whether the given status URI appears at any nesting level.
     * Whitespace inside the URI is ignored because sample responses contain it.
     */
    public function hasStatus(string $code): bool
    {
        foreach ($this->statusCodes as $status) {
            if (str_replace(' ', '', $status) === $code) {
                return true;
            }
        }

        return false;
    }

    public function reason(): string
    {
        return match (true) {
            $this->isAuthnFailed() => 'authn_failed',
            $this->isRequestDenied() => 'request_denied',
            default => 'rejected',
        };
    }

    private static function shortCode(string $code): string
    {
        $position = strrpos($code, ':');

        return trim($position === false ? $code : substr($code, $position + 1));
    }
}
