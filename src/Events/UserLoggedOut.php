<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Events;

use Beziworld\WezelKrajowy\Data\Identity;
use Beziworld\WezelKrajowy\Data\LogoutResult;
use Beziworld\WezelKrajowy\Exceptions\WezelKrajowyException;

/**
 * Dispatched after the local logout; carries the single logout outcome.
 *
 * The result is null when no login.gov.pl session was known or the logout
 * call failed (the exception is set in that case).
 */
final readonly class UserLoggedOut
{
    public function __construct(
        public ?Identity $identity,
        public ?LogoutResult $result = null,
        public ?WezelKrajowyException $exception = null,
    ) {}
}
