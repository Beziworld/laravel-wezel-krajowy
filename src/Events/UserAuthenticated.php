<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Events;

use Beziworld\WezelKrajowy\Data\Identity;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Dispatched after login.gov.pl confirmed an identity and every check passed.
 *
 * The user is set when the identity resolver mapped the identity to a local
 * account and the package logged it in; it is null without a resolver.
 */
final readonly class UserAuthenticated
{
    public function __construct(
        public Identity $identity,
        public ?Authenticatable $user = null,
    ) {}
}
