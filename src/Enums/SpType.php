<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Enums;

/**
 * eIDAS SPType extension value sent in every AuthnRequest.
 */
enum SpType: string
{
    case Public = 'public';
    case Private = 'private';
}
