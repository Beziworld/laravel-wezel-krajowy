<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Data;

/**
 * Verified identity together with the request it answers.
 */
final readonly class AuthenticationResult
{
    public function __construct(
        public Identity $identity,
        public PendingRequest $request,
    ) {}
}
