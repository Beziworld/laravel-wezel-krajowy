<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Http\Controllers;

use Beziworld\WezelKrajowy\Data\Identity;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Events\AuthenticationFailed;
use Beziworld\WezelKrajowy\Events\UserAuthenticated;
use Beziworld\WezelKrajowy\Events\UserLoggedOut;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Beziworld\WezelKrajowy\Exceptions\UserNotResolved;
use Beziworld\WezelKrajowy\Exceptions\WezelKrajowyException;
use Beziworld\WezelKrajowy\Support\SessionState;
use Beziworld\WezelKrajowy\WezelKrajowy;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Routes of the login.gov.pl flow: login, assertion consumer, logout and metadata.
 */
final class WezelKrajowyController
{
    public const string ERROR_FLASH_KEY = 'wezel_krajowy_error';

    public function __construct(
        private readonly WezelKrajowy $service,
        private readonly Dispatcher $events,
        private readonly AuthFactory $auth,
        private readonly ConfigRepository $config,
        private readonly ExceptionHandler $exceptions,
    ) {}

    /**
     * Starts the login: renders the self-submitting AuthnRequest form.
     */
    public function login(Request $request): Response
    {
        $returnTo = $this->safeReturnTo($request, $request->query('return_to'));

        if ($returnTo === null && $request->hasSession()) {
            $returnTo = $this->safeReturnTo($request, $request->session()->get('url.intended'));
        }

        $loa = $request->query('loa');

        return $this->service->redirect($returnTo, is_string($loa) ? LevelOfAssurance::fromName($loa) : null, $request);
    }

    /**
     * Receives the cross-site POST with SAMLart and answers with a 303 to the
     * GET variant, so the browser sends its SameSite=Lax session cookie.
     */
    public function bounce(Request $request): Response|RedirectResponse
    {
        $artifact = $request->input('SAMLart');

        if (! is_string($artifact) || trim($artifact) === '' || strlen($artifact) > 512) {
            return new Response('Missing SAMLart.', 400, ['Content-Type' => 'text/plain; charset=UTF-8']);
        }

        $query = ['SAMLart' => trim($artifact)];
        $relayState = $request->input('RelayState');

        if (is_string($relayState) && $relayState !== '' && strlen($relayState) <= 80) {
            $query['RelayState'] = $relayState;
        }

        return new RedirectResponse($request->url() . '?' . http_build_query($query), 303, ['Cache-Control' => 'no-store']);
    }

    /**
     * Resolves the artifact, validates the assertion and logs the user in.
     */
    public function consume(Request $request): RedirectResponse
    {
        $identity = null;

        try {
            $artifact = $request->query('SAMLart');

            if (! is_string($artifact) || trim($artifact) === '') {
                throw InvalidResponse::because('the request carries no SAMLart');
            }

            $result = $this->service->resolveArtifact($artifact, $request);
            $identity = $result->identity;

            $user = null;

            if ($this->service->hasUserResolver()) {
                $user = $this->service->resolveUser($identity) ?? throw UserNotResolved::make();
                $guard = $this->auth->guard($this->guardName());

                if ($guard instanceof StatefulGuard) {
                    $guard->login($user, (bool) $this->config->get('wezel-krajowy.auth.remember', false));
                }
            }

            if ($request->hasSession()) {
                $request->session()->regenerate();
                SessionState::storeIdentity($request->session(), $identity);
            }

            $this->events->dispatch(new UserAuthenticated($identity, $user));

            return new RedirectResponse($result->request->returnTo ?? $this->path('redirect', '/'));
        } catch (WezelKrajowyException $exception) {
            return $this->failed($request, $exception, $identity);
        }
    }

    /**
     * Logs out locally and, when the session came from login.gov.pl, sends a
     * single logout request. Local logout happens even if the call fails.
     */
    public function logout(Request $request): RedirectResponse
    {
        $identity = $request->hasSession() ? SessionState::identity($request->session()) : null;
        $result = null;
        $failure = null;

        if ($identity !== null) {
            try {
                $result = $this->service->logoutIdentity($identity);
            } catch (WezelKrajowyException $exception) {
                $failure = $exception;
                $this->exceptions->report($exception);
            }
        }

        $guard = $this->auth->guard($this->guardName());

        if ($guard instanceof StatefulGuard && $guard->check()) {
            $guard->logout();
        }

        if ($request->hasSession()) {
            SessionState::forgetIdentity($request->session());
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        $this->events->dispatch(new UserLoggedOut($identity, $result, $failure));

        return new RedirectResponse($this->path('logout_redirect', '/'));
    }

    /**
     * Service provider metadata.
     */
    public function metadata(): Response
    {
        return new Response($this->service->serviceProviderMetadata(), 200, [
            'Content-Type' => 'application/samlmetadata+xml; charset=UTF-8',
        ]);
    }

    private function failed(Request $request, WezelKrajowyException $exception, ?Identity $identity): RedirectResponse
    {
        $this->exceptions->report($exception);
        $this->events->dispatch(new AuthenticationFailed($exception, $exception instanceof UserNotResolved ? $identity : null));

        if ($request->hasSession()) {
            $request->session()->flash(self::ERROR_FLASH_KEY, $exception->reason());
        }

        return new RedirectResponse($this->path('failure_redirect', '/'));
    }

    private function guardName(): ?string
    {
        $guard = $this->config->get('wezel-krajowy.auth.guard');

        return is_string($guard) && $guard !== '' ? $guard : null;
    }

    private function path(string $key, string $default): string
    {
        $value = $this->config->get('wezel-krajowy.auth.' . $key);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    /**
     * Accepts only relative paths or absolute URLs on the current host, which
     * prevents the login flow from being used as an open redirect.
     */
    private function safeReturnTo(Request $request, mixed $value): ?string
    {
        if (! is_string($value) || $value === '' || strlen($value) > 2048 || preg_match('/[\x00-\x1F\\\\]/', $value) === 1) {
            return null;
        }

        if (str_starts_with($value, '/') && ! str_starts_with($value, '//')) {
            return $value;
        }

        $parts = parse_url($value);

        if (! is_array($parts) || ! isset($parts['host'], $parts['scheme']) || ! in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            return null;
        }

        return strcasecmp($parts['host'], $request->getHost()) === 0 ? $value : null;
    }
}
