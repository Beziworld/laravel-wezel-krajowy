<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Events;

use Beziworld\WezelKrajowy\Data\Identity;
use Beziworld\WezelKrajowy\Exceptions\WezelKrajowyException;

/**
 * Dispatched when a login.gov.pl login could not be completed.
 *
 * The identity is set only when the response was valid but no local user
 * matched it.
 */
final readonly class AuthenticationFailed
{
    public function __construct(
        public WezelKrajowyException $exception,
        public ?Identity $identity = null,
    ) {}
}
