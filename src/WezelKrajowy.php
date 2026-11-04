<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy;

use Beziworld\WezelKrajowy\Contracts\IdentityResolver;
use Beziworld\WezelKrajowy\Data\AuthenticationResult;
use Beziworld\WezelKrajowy\Data\AuthnRequestMessage;
use Beziworld\WezelKrajowy\Data\Identity;
use Beziworld\WezelKrajowy\Data\IdpMetadata;
use Beziworld\WezelKrajowy\Data\LogoutResult;
use Beziworld\WezelKrajowy\Data\PendingRequest;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Exceptions\InvalidConfiguration;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Beziworld\WezelKrajowy\Exceptions\ReplayDetected;
use Beziworld\WezelKrajowy\Saml\IdentityProviderCertificates;
use Beziworld\WezelKrajowy\Saml\MessageFactory;
use Beziworld\WezelKrajowy\Saml\Metadata;
use Beziworld\WezelKrajowy\Saml\RequestStore;
use Beziworld\WezelKrajowy\Saml\ResponseProcessor;
use Beziworld\WezelKrajowy\Saml\SoapTransport;
use Beziworld\WezelKrajowy\Security\KeyPair;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Security\XmlSignature;
use Beziworld\WezelKrajowy\Support\SessionState;
use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Service provider side of the login.gov.pl SAML 2.0 artifact profile.
 */
final class WezelKrajowy
{
    private ?KeyPair $signingKey = null;

    private ?KeyPair $encryptionKey = null;

    private ?IdentityProviderCertificates $certificates = null;

    /** @var (Closure(Identity): ?Authenticatable)|null */
    private ?Closure $resolver = null;

    public function __construct(
        private readonly WezelKrajowyConfig $config,
        private readonly HttpFactory $http,
        private readonly CacheFactory $cache,
        private readonly UrlGenerator $url,
        private readonly Container $container,
        private readonly ?string $resolverClass = null,
    ) {}

    public function config(): WezelKrajowyConfig
    {
        return $this->config;
    }

    /**
     * Assertion consumer URL registered with COI: the configured value or the package route.
     */
    public function acsUrl(): string
    {
        return $this->config->acsUrl ?? $this->url->route('wezel-krajowy.acs');
    }

    /**
     * Creates, signs and registers an AuthnRequest.
     *
     * A requested level of assurance lower than the configured one is raised
     * to the configured minimum. The request ID is remembered in the session
     * of the given (or current) HTTP request when one is available, so that
     * resolveArtifact() can bind the response to the same browser.
     */
    public function authnRequest(?string $returnTo = null, ?LevelOfAssurance $levelOfAssurance = null, ?Request $request = null): AuthnRequestMessage
    {
        $loa = $levelOfAssurance !== null && $levelOfAssurance->satisfies($this->config->levelOfAssurance)
            ? $levelOfAssurance
            : $this->config->levelOfAssurance;

        $now = CarbonImmutable::now();
        $pending = new PendingRequest(Xml::newId(), $loa, $this->acsUrl(), $now, $returnTo);
        $xml = $this->messages()->authnRequest($pending->id, $pending->acsUrl, $loa, $now);

        $this->store()->put($pending);

        $request ??= $this->currentRequest();

        if ($request !== null && $request->hasSession()) {
            SessionState::rememberRequest($request->session(), $pending->id);
        }

        $fields = ['SAMLRequest' => base64_encode($xml)];

        if ($this->config->foreignAuthentication) {
            $fields['ForeignAuthentication'] = 'true';
        }

        return new AuthnRequestMessage($pending, $this->config->ssoUrl(), $xml, $fields);
    }

    /**
     * HTTP response with the self-submitting form that starts the login.
     * The request ID is remembered in the session when one is available.
     */
    public function redirect(?string $returnTo = null, ?LevelOfAssurance $levelOfAssurance = null, ?Request $request = null): Response
    {
        $message = $this->authnRequest($returnTo, $levelOfAssurance, $request);

        return new Response($message->toHtml(), 200, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Cache-Control' => 'no-store, no-cache, must-revalidate',
            'Pragma' => 'no-cache',
        ]);
    }

    /**
     * Resolves a SAML artifact over the SOAP back channel and validates the result.
     *
     * With "security.bind_to_session" enabled (the default) the answered
     * AuthnRequest must have been started in the session of the given (or
     * current) HTTP request; otherwise ReplayDetected is thrown. This stops
     * login CSRF, where a victim is sent to the assertion consumer with an
     * artifact that was issued for the attacker's own login.
     *
     * @throws ReplayDetected
     */
    public function resolveArtifact(string $artifact, ?Request $request = null): AuthenticationResult
    {
        $artifact = trim($artifact);
        $decoded = strlen($artifact) <= 512 ? base64_decode($artifact, true) : false;

        if ($decoded === false || strlen($decoded) !== 44 || substr($decoded, 0, 2) !== "\x00\x04") {
            throw InvalidResponse::because('SAMLart is not a SAML 2.0 type 0x0004 artifact');
        }

        $id = Xml::newId();
        $envelope = $this->messages()->artifactResolve($id, $artifact, CarbonImmutable::now());
        $element = $this->transport()->send($this->config->artifactResolutionUrl(), $envelope);

        $result = (new ResponseProcessor($this->config, $this->encryptionKey(), $this->store()))
            ->process($element, $id, $this->certificates()->all());

        if ($this->config->bindToSession) {
            $request ??= $this->currentRequest();

            if ($request === null || ! $request->hasSession() || ! SessionState::forgetRequest($request->session(), $result->request->id)) {
                throw ReplayDetected::foreignSession($result->request->id);
            }
        }

        return $result;
    }

    /**
     * Sends a signed LogoutRequest for the given session over the SOAP back channel.
     */
    public function logout(string $nameId, ?string $sessionIndex, ?string $nameIdFormat = null): LogoutResult
    {
        $id = Xml::newId();
        $envelope = $this->messages()->logoutRequest($id, $nameId, $nameIdFormat, $sessionIndex, CarbonImmutable::now());
        $element = $this->transport()->send($this->config->singleLogoutUrl(), $envelope);

        if ($element->namespaceURI !== Xml::SAMLP || $element->localName !== 'LogoutResponse') {
            throw InvalidResponse::because('the logout service did not return a LogoutResponse');
        }

        XmlSignature::verify($element, $this->certificates()->all());

        if (Xml::attribute($element, 'InResponseTo') !== $id) {
            throw InvalidResponse::because('LogoutResponse InResponseTo does not match the LogoutRequest ID');
        }

        [$codes, $message] = ResponseProcessor::status($element);

        return new LogoutResult($id, Xml::attribute($element, 'ID'), $codes, $message, [
            'issuer' => Xml::text(Xml::child($element, Xml::SAML, 'Issuer')),
            'issue_instant' => Xml::attribute($element, 'IssueInstant'),
        ]);
    }

    public function logoutIdentity(Identity $identity): LogoutResult
    {
        return $this->logout($identity->nameId, $identity->sessionIndex, $identity->nameIdFormat);
    }

    /**
     * Service provider metadata XML (for documentation and COI onboarding).
     */
    public function serviceProviderMetadata(): string
    {
        return Metadata::serviceProvider(
            $this->config,
            $this->acsUrl(),
            $this->signingKey()->certificate(),
            $this->encryptionKey()->certificate(),
        );
    }

    /**
     * Public metadata of the configured login.gov.pl environment.
     */
    public function identityProviderMetadata(bool $fresh = false): IdpMetadata
    {
        return $this->certificates()->metadata($fresh);
    }

    /**
     * Registers the callback (or resolver instance) that maps identities to users.
     *
     * @param (Closure(Identity): ?Authenticatable)|IdentityResolver|null $resolver
     */
    public function resolveUsersUsing(Closure|IdentityResolver|null $resolver): self
    {
        $this->resolver = $resolver instanceof IdentityResolver ? $resolver->resolve(...) : $resolver;

        return $this;
    }

    public function hasUserResolver(): bool
    {
        return $this->resolver !== null || $this->resolverClass !== null;
    }

    /**
     * Maps an identity to a local user with the registered resolver.
     */
    public function resolveUser(Identity $identity): ?Authenticatable
    {
        if ($this->resolver !== null) {
            return ($this->resolver)($identity);
        }

        if ($this->resolverClass === null) {
            return null;
        }

        $resolver = $this->container->make($this->resolverClass);

        if (! $resolver instanceof IdentityResolver) {
            throw InvalidConfiguration::invalid('auth.resolver', 'the auth.resolver setting', 'the class must implement ' . IdentityResolver::class);
        }

        return $resolver->resolve($identity);
    }

    /**
     * Identity of the current browser session, if the user logged in with login.gov.pl.
     */
    public function identity(?Request $request = null): ?Identity
    {
        $request ??= $this->currentRequest();

        return $request !== null && $request->hasSession() ? SessionState::identity($request->session()) : null;
    }

    public function signingKey(): KeyPair
    {
        return $this->signingKey ??= KeyPair::load(
            $this->config->signingKey,
            $this->config->signingCertificate,
            $this->config->signingPassphrase,
            'sp.signing',
        );
    }

    public function encryptionKey(): KeyPair
    {
        return $this->encryptionKey ??= KeyPair::load(
            $this->config->encryptionKey,
            $this->config->encryptionCertificate,
            $this->config->encryptionPassphrase,
            'sp.encryption',
        );
    }

    public function certificates(): IdentityProviderCertificates
    {
        return $this->certificates ??= new IdentityProviderCertificates($this->config, $this->http, $this->cacheStore());
    }

    private function messages(): MessageFactory
    {
        return new MessageFactory($this->config, $this->signingKey());
    }

    private function transport(): SoapTransport
    {
        return new SoapTransport($this->http, $this->config);
    }

    private function store(): RequestStore
    {
        return new RequestStore($this->cacheStore(), $this->config->requestTtl);
    }

    private function cacheStore(): CacheRepository
    {
        return $this->cache->store($this->config->cacheStore);
    }

    private function currentRequest(): ?Request
    {
        if (! $this->container->bound('request')) {
            return null;
        }

        return $this->container->make('request');
    }
}
