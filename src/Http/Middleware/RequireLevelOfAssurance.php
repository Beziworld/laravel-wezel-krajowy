<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Http\Middleware;

use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Exceptions\InvalidConfiguration;
use Beziworld\WezelKrajowy\Support\SessionState;
use Closure;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * Requires a login.gov.pl identity of at least the given level of assurance
 * in the session (alias "wezel-krajowy.loa", for example "wezel-krajowy.loa:high").
 *
 * Browsers are sent through the login flow with the level raised; JSON
 * requests receive 401.
 */
final class RequireLevelOfAssurance
{
    public function __construct(
        private readonly UrlGenerator $url,
    ) {}

    /**
     * @param Closure(Request): SymfonyResponse $next
     */
    public function handle(Request $request, Closure $next, string $level = 'substantial'): SymfonyResponse
    {
        $required = LevelOfAssurance::fromName($level)
            ?? throw InvalidConfiguration::invalid('middleware level', 'the wezel-krajowy.loa middleware parameter', 'expected low, substantial or high');

        $identity = $request->hasSession() ? SessionState::identity($request->session()) : null;

        if ($identity !== null && $identity->satisfies($required)) {
            return $next($request);
        }

        if ($request->expectsJson()) {
            return new Response('A login.gov.pl login with the ' . $required->shortName() . ' level of assurance is required.', 401);
        }

        return new RedirectResponse($this->url->route('wezel-krajowy.login', [
            'loa' => $required->shortName(),
            'return_to' => $request->getRequestUri(),
        ]));
    }
}
