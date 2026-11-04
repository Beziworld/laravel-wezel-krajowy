<?php

declare(strict_types=1);

use Beziworld\WezelKrajowy\Http\Controllers\WezelKrajowyController;
use Illuminate\Support\Facades\Route;

/** @var array{prefix?: mixed, middleware?: mixed, domain?: mixed} $routes */
$routes = (array) config('wezel-krajowy.routes', []);
$prefix = is_string($routes['prefix'] ?? null) ? $routes['prefix'] : 'wezel-krajowy';
$middleware = is_array($routes['middleware'] ?? null) ? array_values(array_filter($routes['middleware'], 'is_string')) : ['web'];
$domain = is_string($routes['domain'] ?? null) ? $routes['domain'] : null;

$group = Route::prefix($prefix)->name('wezel-krajowy.');

if ($domain !== null) {
    $group->domain($domain);
}

$group->group(static function () use ($middleware): void {
    Route::middleware($middleware)->group(static function (): void {
        Route::get('login', [WezelKrajowyController::class, 'login'])->name('login');
        Route::get('acs', [WezelKrajowyController::class, 'consume'])->name('acs');
        Route::post('logout', [WezelKrajowyController::class, 'logout'])->name('logout');
        Route::get('metadata', [WezelKrajowyController::class, 'metadata'])->name('metadata');
    });

    // The cross-site POST from login.gov.pl carries no CSRF token and no Lax session cookie.
    Route::post('acs', [WezelKrajowyController::class, 'bounce'])->name('acs.post');
});
