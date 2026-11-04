<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Saml;

use Beziworld\WezelKrajowy\Data\AuthenticationResult;
use Beziworld\WezelKrajowy\Data\Identity;
use Beziworld\WezelKrajowy\Data\PendingRequest;
use Beziworld\WezelKrajowy\Enums\EidasAttribute;
use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Exceptions\AuthenticationRejected;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Beziworld\WezelKrajowy\Exceptions\ReplayDetected;
use Beziworld\WezelKrajowy\Security\Certificate;
use Beziworld\WezelKrajowy\Security\Decrypter;
use Beziworld\WezelKrajowy\Security\KeyPair;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Security\XmlSignature;
use Beziworld\WezelKrajowy\Support\Pesel;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;
use Carbon\CarbonImmutable;
use DOMElement;

/**
 * Validates an ArtifactResponse and turns its assertion into an Identity.
 *
 * Checks performed: signatures of ArtifactResponse, Response and (when
 * present) Assertion against the trusted login.gov.pl certificates;
 * InResponseTo of every layer; one-time use of the AuthnRequest; SAML
 * status; Destination and Recipient; NotBefore and NotOnOrAfter with clock
 * skew; audience; level of assurance; assertion replay; mandatory attributes.
 */
final class ResponseProcessor
{
    public const string SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    private const string BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

    public function __construct(
        private readonly WezelKrajowyConfig $config,
        private readonly KeyPair $decryptionKey,
        private readonly RequestStore $store,
    ) {}

    /**
     * @param list<Certificate> $trusted
     *
     * @throws InvalidResponse|AuthenticationRejected|ReplayDetected
     */
    public function process(DOMElement $artifactResponse, string $artifactResolveId, array $trusted): AuthenticationResult
    {
        $now = CarbonImmutable::now();

        if ($artifactResponse->namespaceURI !== Xml::SAMLP || $artifactResponse->localName !== 'ArtifactResponse') {
            throw InvalidResponse::because('the back channel did not return an ArtifactResponse');
        }

        XmlSignature::verify($artifactResponse, $trusted);
        $this->checkMessage($artifactResponse, $now);

        if (Xml::attribute($artifactResponse, 'InResponseTo') !== $artifactResolveId) {
            throw InvalidResponse::because('ArtifactResponse InResponseTo does not match the ArtifactResolve ID');
        }

        [$codes, $message] = self::status($artifactResponse);

        if (($codes[0] ?? null) !== self::SUCCESS) {
            throw new AuthenticationRejected($codes, $message);
        }

        if (Xml::children($artifactResponse, Xml::SAMLP, 'Response') === []) {
            throw InvalidResponse::because('the artifact did not resolve to a Response (it may have expired or been used)');
        }

        $response = Xml::single($artifactResponse, Xml::SAMLP, 'Response');

        $requestId = Xml::attribute($response, 'InResponseTo');
        [$codes, $message] = self::status($response);

        if (($codes[0] ?? null) !== self::SUCCESS) {
            if ($requestId !== null) {
                $this->store->pull($requestId);
            }

            throw new AuthenticationRejected($codes, $message);
        }

        if ($this->config->requireSignedResponse || XmlSignature::isSigned($response)) {
            XmlSignature::verify($response, $trusted);
        }

        $this->checkMessage($response, $now);

        $encrypted = Xml::children($response, Xml::SAML, 'EncryptedAssertion');

        if (Xml::children($response, Xml::SAML, 'Assertion') !== [] || count($encrypted) !== 1) {
            throw InvalidResponse::because('the Response must contain exactly one encrypted assertion');
        }

        $assertion = Decrypter::decryptAssertion($encrypted[0], $this->decryptionKey);

        if (XmlSignature::isSigned($assertion)) {
            XmlSignature::verify($assertion, $trusted);
        }

        $confirmations = $this->bearerConfirmations($assertion);
        $requestId ??= $confirmations[0]['in_response_to'] ?? null;

        if ($requestId === null) {
            throw InvalidResponse::because('the Response does not say which AuthnRequest it answers');
        }

        $pending = $this->store->pull($requestId) ?? throw ReplayDetected::unknownRequest($requestId);

        $destination = Xml::attribute($response, 'Destination');

        if ($destination !== null && $destination !== $pending->acsUrl) {
            throw InvalidResponse::because('Response Destination does not match the assertion consumer URL');
        }

        return new AuthenticationResult($this->identity($assertion, $confirmations, $pending, $now), $pending);
    }

    /**
     * Status codes (outermost first) and the status message of a SAML message.
     *
     * @return array{0: list<string>, 1: string|null}
     */
    public static function status(DOMElement $message): array
    {
        $status = Xml::child($message, Xml::SAMLP, 'Status');
        $codes = [];
        $current = $status !== null ? Xml::child($status, Xml::SAMLP, 'StatusCode') : null;

        while ($current !== null) {
            $codes[] = trim($current->getAttribute('Value'));
            $current = Xml::child($current, Xml::SAMLP, 'StatusCode');
        }

        $text = $status !== null ? Xml::text(Xml::child($status, Xml::SAMLP, 'StatusMessage')) : null;

        return [$codes, $text];
    }

    /**
     * Version, Issuer and IssueInstant sanity checks shared by all layers.
     *
     * The Issuer is optional on protocol messages but mandatory on an
     * assertion (SAML 2.0 Core, section 2.3.3). When the identity provider
     * entity ID is configured, every Issuer present must match it.
     */
    private function checkMessage(DOMElement $message, CarbonImmutable $now, bool $issuerRequired = false): void
    {
        if ($message->getAttribute('Version') !== '2.0') {
            throw InvalidResponse::because(sprintf('%s Version must be 2.0', $message->localName));
        }

        $this->checkIssuer($message, $issuerRequired);

        $issued = Xml::parseInstant(Xml::attribute($message, 'IssueInstant'), $message->localName . ' IssueInstant');

        if ($issued->greaterThan($now->addSeconds($this->config->clockSkew))
            || $issued->lessThan($now->subSeconds($this->config->requestTtl + $this->config->clockSkew))) {
            throw InvalidResponse::because(sprintf('%s IssueInstant is outside the accepted time window', $message->localName));
        }
    }

    private function checkIssuer(DOMElement $message, bool $required): void
    {
        $issuer = Xml::text(Xml::child($message, Xml::SAML, 'Issuer'));

        if ($required && $issuer === null) {
            throw InvalidResponse::because(sprintf('the %s has no Issuer', $message->localName));
        }

        if ($this->config->idpEntityId !== null && $issuer !== null && $issuer !== $this->config->idpEntityId) {
            throw InvalidResponse::because(sprintf('unexpected %s Issuer "%s"', $message->localName, $issuer));
        }
    }

    /**
     * @return list<array{in_response_to: string|null, recipient: string|null, not_on_or_after: string|null, not_before: string|null}>
     */
    private function bearerConfirmations(DOMElement $assertion): array
    {
        $subject = Xml::child($assertion, Xml::SAML, 'Subject');
        $confirmations = [];

        foreach ($subject !== null ? Xml::children($subject, Xml::SAML, 'SubjectConfirmation') : [] as $confirmation) {
            if ($confirmation->getAttribute('Method') !== self::BEARER) {
                continue;
            }

            $data = Xml::child($confirmation, Xml::SAML, 'SubjectConfirmationData');

            $confirmations[] = [
                'in_response_to' => $data !== null ? Xml::attribute($data, 'InResponseTo') : null,
                'recipient' => $data !== null ? Xml::attribute($data, 'Recipient') : null,
                'not_on_or_after' => $data !== null ? Xml::attribute($data, 'NotOnOrAfter') : null,
                'not_before' => $data !== null ? Xml::attribute($data, 'NotBefore') : null,
            ];
        }

        return $confirmations;
    }

    /**
     * @param list<array{in_response_to: string|null, recipient: string|null, not_on_or_after: string|null, not_before: string|null}> $confirmations
     */
    private function identity(DOMElement $assertion, array $confirmations, PendingRequest $pending, CarbonImmutable $now): Identity
    {
        $skew = $this->config->clockSkew;
        $assertionId = Xml::attribute($assertion, 'ID') ?? throw InvalidResponse::because('the assertion has no ID');
        $this->checkMessage($assertion, $now, true);

        $subject = Xml::single($assertion, Xml::SAML, 'Subject');
        $nameIdElement = Xml::single($subject, Xml::SAML, 'NameID');
        $nameId = Xml::text($nameIdElement) ?? throw InvalidResponse::because('the assertion NameID is empty');

        $expiry = $this->validConfirmation($confirmations, $pending, $now);

        $conditions = Xml::child($assertion, Xml::SAML, 'Conditions')
            ?? throw InvalidResponse::because('the assertion has no Conditions');

        $notBefore = Xml::attribute($conditions, 'NotBefore');

        if ($notBefore !== null && Xml::parseInstant($notBefore, 'Conditions NotBefore')->greaterThan($now->addSeconds($skew))) {
            throw InvalidResponse::because('the assertion is not valid yet (Conditions NotBefore)');
        }

        $notOnOrAfter = Xml::attribute($conditions, 'NotOnOrAfter');

        if ($notOnOrAfter !== null) {
            $conditionsExpiry = Xml::parseInstant($notOnOrAfter, 'Conditions NotOnOrAfter');

            if ($conditionsExpiry->lessThanOrEqualTo($now->subSeconds($skew))) {
                throw InvalidResponse::because('the assertion has expired (Conditions NotOnOrAfter)');
            }

            $expiry = $conditionsExpiry->lessThan($expiry) ? $conditionsExpiry : $expiry;
        }

        $this->checkAudience($conditions);

        $statement = Xml::children($assertion, Xml::SAML, 'AuthnStatement')[0]
            ?? throw InvalidResponse::because('the assertion has no AuthnStatement');

        $sessionNotOnOrAfter = Xml::attribute($statement, 'SessionNotOnOrAfter');

        if ($sessionNotOnOrAfter !== null && Xml::parseInstant($sessionNotOnOrAfter, 'SessionNotOnOrAfter')->lessThanOrEqualTo($now->subSeconds($skew))) {
            throw InvalidResponse::because('the authentication session has expired (SessionNotOnOrAfter)');
        }

        $context = Xml::child($statement, Xml::SAML, 'AuthnContext');
        $classRef = $context !== null ? Xml::text(Xml::child($context, Xml::SAML, 'AuthnContextClassRef')) : null;
        $loa = $classRef !== null ? LevelOfAssurance::tryFrom($classRef) : null;

        if ($loa === null) {
            throw InvalidResponse::because('the assertion does not state a known eIDAS level of assurance');
        }

        if (! $loa->satisfies($pending->levelOfAssurance)) {
            throw InvalidResponse::because(sprintf(
                'level of assurance "%s" is lower than the required "%s"',
                $loa->shortName(),
                $pending->levelOfAssurance->shortName(),
            ));
        }

        $authority = Xml::text(Xml::child($context, Xml::SAML, 'AuthenticatingAuthority'));
        $authnInstant = Xml::attribute($statement, 'AuthnInstant');

        if (! $this->store->consumeAssertion($assertionId, $expiry)) {
            throw ReplayDetected::assertion($assertionId);
        }

        [$attributes, $byName] = $this->attributes($assertion);

        foreach (EidasAttribute::mandatory() as $mandatory) {
            $values = $attributes[$mandatory->name] ?? [];

            if (! isset($values[0]) || trim($values[0]) === '') {
                throw InvalidResponse::because(sprintf('the mandatory attribute %s is missing', $mandatory->name));
            }

            if (count($values) > 1) {
                throw InvalidResponse::because(sprintf('the mandatory attribute %s has more than one value', $mandatory->name));
            }
        }

        $birth = $attributes[EidasAttribute::DateOfBirth->name][0];

        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $birth, $date) !== 1 || ! checkdate((int) $date[2], (int) $date[3], (int) $date[1])) {
            throw InvalidResponse::because('DateOfBirth is not a valid date');
        }

        $identifier = $attributes[EidasAttribute::PersonIdentifier->name][0];

        return new Identity(
            firstName: $attributes[EidasAttribute::FirstName->name][0],
            familyName: $attributes[EidasAttribute::FamilyName->name][0],
            dateOfBirth: CarbonImmutable::parse($birth, Identity::TIMEZONE)->startOfDay(),
            personIdentifier: $identifier,
            pesel: Pesel::fromPersonIdentifier($identifier),
            levelOfAssurance: $loa,
            identityProvider: $authority,
            nameId: $nameId,
            nameIdFormat: Xml::attribute($nameIdElement, 'Format'),
            sessionIndex: Xml::attribute($statement, 'SessionIndex'),
            assertionId: $assertionId,
            authenticatedAt: $authnInstant !== null ? Xml::parseInstant($authnInstant, 'AuthnInstant') : $now,
            attributes: $attributes,
            raw: [
                'issuer' => Xml::text(Xml::child($assertion, Xml::SAML, 'Issuer')),
                'request_id' => $pending->id,
                'attributes' => $byName,
                'expires_at' => $expiry->toIso8601ZuluString('millisecond'),
            ],
        );
    }

    /**
     * Finds a bearer confirmation that matches this request and returns its expiry.
     *
     * @param list<array{in_response_to: string|null, recipient: string|null, not_on_or_after: string|null, not_before: string|null}> $confirmations
     */
    private function validConfirmation(array $confirmations, PendingRequest $pending, CarbonImmutable $now): CarbonImmutable
    {
        $skew = $this->config->clockSkew;
        $failure = 'the assertion has no bearer SubjectConfirmation';

        foreach ($confirmations as $confirmation) {
            if ($confirmation['in_response_to'] !== $pending->id) {
                $failure = 'SubjectConfirmationData InResponseTo does not match the AuthnRequest';

                continue;
            }

            if ($confirmation['recipient'] === null || $confirmation['recipient'] !== $pending->acsUrl) {
                $failure = 'SubjectConfirmationData Recipient does not match the assertion consumer URL';

                continue;
            }

            if ($confirmation['not_on_or_after'] === null) {
                $failure = 'SubjectConfirmationData has no NotOnOrAfter';

                continue;
            }

            $expiry = Xml::parseInstant($confirmation['not_on_or_after'], 'SubjectConfirmationData NotOnOrAfter');

            if ($expiry->lessThanOrEqualTo($now->subSeconds($skew))) {
                $failure = 'the assertion has expired (SubjectConfirmationData NotOnOrAfter)';

                continue;
            }

            if ($confirmation['not_before'] !== null
                && Xml::parseInstant($confirmation['not_before'], 'SubjectConfirmationData NotBefore')->greaterThan($now->addSeconds($skew))) {
                $failure = 'the assertion is not valid yet (SubjectConfirmationData NotBefore)';

                continue;
            }

            return $expiry;
        }

        throw InvalidResponse::because($failure);
    }

    private function checkAudience(DOMElement $conditions): void
    {
        $restrictions = Xml::children($conditions, Xml::SAML, 'AudienceRestriction');

        if ($restrictions === []) {
            throw InvalidResponse::because('the assertion has no AudienceRestriction');
        }

        foreach ($restrictions as $restriction) {
            $audiences = array_map(static fn(DOMElement $audience): ?string => Xml::text($audience), Xml::children($restriction, Xml::SAML, 'Audience'));

            if (! in_array($this->config->entityId, $audiences, true)) {
                throw InvalidResponse::because('the assertion audience does not include this service provider');
            }
        }
    }

    /**
     * Collects attribute values keyed for lookup and keyed by Name.
     *
     * Attributes with a known eIDAS Name are keyed by the enum case name.
     * Any other attribute is keyed by its FriendlyName unless that
     * FriendlyName collides with an eIDAS case name, in which case the Name
     * is used, so that an unknown attribute can never supply the value of a
     * well-known one such as PersonIdentifier.
     *
     * @return array{0: array<string, list<string>>, 1: array<string, list<string>>}
     */
    private function attributes(DOMElement $assertion): array
    {
        $byKey = [];
        $byName = [];

        foreach (Xml::children($assertion, Xml::SAML, 'AttributeStatement') as $statement) {
            foreach (Xml::children($statement, Xml::SAML, 'Attribute') as $attribute) {
                $name = Xml::attribute($attribute, 'Name');

                if ($name === null) {
                    continue;
                }

                $values = [];

                foreach (Xml::children($attribute, Xml::SAML, 'AttributeValue') as $value) {
                    $values[] = trim($value->textContent);
                }

                $known = EidasAttribute::tryFrom($name);
                $friendlyName = Xml::attribute($attribute, 'FriendlyName');
                $key = match (true) {
                    $known !== null => $known->name,
                    $friendlyName !== null && EidasAttribute::fromFriendlyName($friendlyName) === null => $friendlyName,
                    default => $name,
                };

                $byKey[$key] = array_merge($byKey[$key] ?? [], $values);
                $byName[$name] = array_merge($byName[$name] ?? [], $values);
            }
        }

        return [$byKey, $byName];
    }
}
