<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Exceptions;

use RuntimeException;

/**
 * Base exception of the package.
 */
class WezelKrajowyException extends RuntimeException
{
    /**
     * Short, stable identifier of the failure category, safe to show to users or log.
     */
    public function reason(): string
    {
        return 'error';
    }
}
