<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Contracts;

use Beziworld\WezelKrajowy\Data\Identity;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Maps an identity confirmed by login.gov.pl to a local user account.
 *
 * Return null to refuse the login (for example when no account is linked to
 * the PESEL). Implementations may create accounts on first login.
 */
interface IdentityResolver
{
    public function resolve(Identity $identity): ?Authenticatable;
}
