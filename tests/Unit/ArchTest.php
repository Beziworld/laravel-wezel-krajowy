<?php

declare(strict_types=1);

arch('every source file declares strict types')
    ->expect('Beziworld\WezelKrajowy')
    ->toUseStrictTypes();

arch('no debugging statements are left behind')
    ->expect(['dd', 'dump', 'ray', 'var_dump', 'print_r', 'die'])
    ->not->toBeUsed();

arch('data objects are immutable')
    ->expect('Beziworld\WezelKrajowy\Data')
    ->toBeReadonly();

arch('exceptions share the package base exception')
    ->expect('Beziworld\WezelKrajowy\Exceptions')
    ->toExtend('Beziworld\WezelKrajowy\Exceptions\WezelKrajowyException')
    ->ignoring('Beziworld\WezelKrajowy\Exceptions\WezelKrajowyException');
