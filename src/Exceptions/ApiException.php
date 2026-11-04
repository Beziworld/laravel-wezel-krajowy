<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Exceptions;

use Throwable;

/**
 * Raised when a back-channel call to login.gov.pl fails or cannot be reached.
 */
final class ApiException extends WezelKrajowyException
{
    public function __construct(
        string $message,
        public readonly string $endpoint,
        public readonly ?int $httpStatus = null,
        public readonly ?string $faultString = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, $httpStatus ?? 0, $previous);
    }

    public static function http(string $endpoint, int $status, ?string $faultString = null): self
    {
        return new self(
            sprintf('login.gov.pl call to %s failed with HTTP status %d%s.', $endpoint, $status, $faultString !== null ? ' (' . $faultString . ')' : ''),
            $endpoint,
            $status,
            $faultString,
        );
    }

    public static function transport(string $endpoint, Throwable $previous): self
    {
        return new self('Could not connect to login.gov.pl: ' . $previous->getMessage(), $endpoint, null, null, $previous);
    }

    public static function invalidResponse(string $endpoint, string $detail): self
    {
        return new self(sprintf('login.gov.pl call to %s returned an unexpected response: %s.', $endpoint, $detail), $endpoint, 200);
    }

    public function isServerError(): bool
    {
        return $this->httpStatus !== null && $this->httpStatus >= 500;
    }

    public function reason(): string
    {
        return 'unavailable';
    }
}
