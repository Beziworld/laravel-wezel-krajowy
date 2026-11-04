<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Tests\Support;

use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Security\XmlSignature;
use Carbon\CarbonImmutable;
use Closure;
use DOMDocument;
use DOMElement;

/**
 * Builds login.gov.pl back-channel responses for tests, modelled on the
 * examples of the service provider integration guide.
 */
final class FakeLoginGovPl
{
    public const string ARTIFACT = 'AAQAAcnceygFBb+m6oU0QfFClgJEIo9xVz7eKhr4hDP11aX2WDl2yxUS+7A=';

    public const string ACS = 'http://localhost/wezel-krajowy/acs';

    public const string ENTITY_ID = 'https://sp.example.pl';

    public const string SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    /**
     * @param array<string, mixed> $overrides
     */
    public static function assertion(string $requestId, array $overrides = []): string
    {
        $now = CarbonImmutable::now();
        $o = array_merge([
            'id' => '_ID-' . bin2hex(random_bytes(8)),
            'issue_instant' => $now,
            'in_response_to' => $requestId,
            'recipient' => self::ACS,
            'confirmation_not_on_or_after' => $now->addMinutes(5),
            'not_before' => $now->subSecond(),
            'not_on_or_after' => $now->addMinutes(5),
            'audience' => self::ENTITY_ID,
            'loa' => 'http://eidas.europa.eu/LoA/substantial',
            'authority' => 'pz.gov.pl',
            'session_index' => '_ID-session-1',
            'name_id' => 'AVIphXW7D/K5s/tQmpMb04KBg8nDuBuFwVYZ2vtZ6lw=',
            'issuer' => 'login.gov.pl',
            'attributes' => [
                'FirstName' => ['http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName', 'Jan'],
                'FamilyName' => ['http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName', 'Niezbędny'],
                'PersonIdentifier' => ['http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier', '86072500004'],
                'DateOfBirth' => ['http://eidas.europa.eu/attributes/naturalperson/DateOfBirth', '1986-07-25'],
            ],
        ], $overrides);

        $attributes = '';

        foreach ($o['attributes'] as $key => $specification) {
            [$name, $value] = $specification;
            $friendly = $specification[2] ?? $key;
            $attributes .= sprintf(
                '<saml2:Attribute FriendlyName="%s" Name="%s" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="naturalperson:%sType">%s</saml2:AttributeValue></saml2:Attribute>',
                $friendly,
                $name,
                $friendly,
                htmlspecialchars($value, ENT_XML1),
            );
        }

        return sprintf(
            '<saml2:Assertion xmlns:saml2="%s" xmlns:ds="%s" xmlns:naturalperson="%s" xmlns:xsi="%s" ID="%s" IssueInstant="%s" Version="2.0">'
            . '%s'
            . '<saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">%s</saml2:NameID>'
            . '<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="%s" NotOnOrAfter="%s" Recipient="%s"/></saml2:SubjectConfirmation></saml2:Subject>'
            . '<saml2:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>'
            . '<saml2:AuthnStatement AuthnInstant="%s" SessionIndex="%s"><saml2:AuthnContext><saml2:AuthnContextClassRef>%s</saml2:AuthnContextClassRef><saml2:AuthenticatingAuthority>%s</saml2:AuthenticatingAuthority></saml2:AuthnContext></saml2:AuthnStatement>'
            . '<saml2:AttributeStatement>%s</saml2:AttributeStatement></saml2:Assertion>',
            Xml::SAML,
            Xml::DS,
            Xml::NATURAL_PERSON,
            Xml::XSI,
            $o['id'],
            Xml::instant($o['issue_instant']),
            $o['issuer'] !== null ? '<saml2:Issuer>' . htmlspecialchars($o['issuer'], ENT_XML1) . '</saml2:Issuer>' : '',
            $o['name_id'],
            $o['in_response_to'],
            Xml::instant($o['confirmation_not_on_or_after']),
            $o['recipient'],
            Xml::instant($o['not_before']),
            Xml::instant($o['not_on_or_after']),
            $o['audience'],
            Xml::instant($o['issue_instant']),
            $o['session_index'],
            $o['loa'],
            $o['authority'],
            $attributes,
        );
    }

    /**
     * SOAP envelope with a signed ArtifactResponse.
     *
     * The "mutate" option changes the document before it is signed (content
     * that login.gov.pl itself would vouch for), the "tamper" option after
     * signing (content injected by an attacker).
     *
     * @param array<string, mixed> $options
     */
    public static function artifactResponse(string $artifactResolveId, string $requestId, array $options = []): string
    {
        $o = array_merge([
            'assertion' => [],
            'status' => [self::SUCCESS],
            'status_message' => null,
            'outer_status' => [self::SUCCESS],
            'encrypt' => 'ecdh',
            'recipient_key' => 'sp-encryption',
            'outer_key' => 'idp',
            'inner_key' => 'idp',
            'sign_outer' => true,
            'sign_inner' => true,
            'sign_assertion' => false,
            'with_response' => true,
            'response_in_response_to' => $requestId,
            'destination' => self::ACS,
            'mutate' => null,
            'tamper' => null,
        ], $options);

        $assertion = self::assertion($requestId, $o['assertion']);

        if ($o['sign_assertion']) {
            $document = Xml::load($assertion);
            XmlSignature::sign(self::root($document), Keys::pair('idp'));
            $assertion = (string) $document->saveXML(self::root($document));
        }

        $assertionXml = match ($o['encrypt']) {
            'ecdh' => Encrypter::ecdhEs($assertion, Keys::certificate($o['recipient_key'])),
            'rsa' => Encrypter::rsaOaep($assertion, Keys::certificate($o['recipient_key'])),
            default => $assertion,
        };

        $isSuccess = ($o['status'][0] ?? null) === self::SUCCESS;
        $now = Xml::instant(CarbonImmutable::now());

        $response = $o['with_response'] ? sprintf(
            '<saml2p:Response ID="ID-resp-%s"%s%s IssueInstant="%s" Version="2.0"><saml2:Issuer>login.gov.pl</saml2:Issuer>%s%s</saml2p:Response>',
            bin2hex(random_bytes(6)),
            $o['response_in_response_to'] !== null ? sprintf(' InResponseTo="%s"', $o['response_in_response_to']) : '',
            $o['destination'] !== null ? sprintf(' Destination="%s"', $o['destination']) : '',
            $now,
            self::status($o['status'], $o['status_message']),
            $isSuccess ? $assertionXml : '',
        ) : '';

        $outerId = 'ID-ar-' . bin2hex(random_bytes(6));
        $xml = sprintf(
            '<soap:Envelope xmlns:soap="%s"><soap:Header/><soap:Body>'
            . '<saml2p:ArtifactResponse xmlns:saml2p="%s" xmlns:saml2="%s" xmlns:ds="%s" xmlns:xenc="%s" Consent="urn:oasis:names:tc:SAML:2.0:consent:obtained" ID="%s" InResponseTo="%s" IssueInstant="%s" Version="2.0">'
            . '<saml2:Issuer>login.gov.pl</saml2:Issuer>%s%s</saml2p:ArtifactResponse></soap:Body></soap:Envelope>',
            Xml::SOAP,
            Xml::SAMLP,
            Xml::SAML,
            Xml::DS,
            Xml::XENC,
            $outerId,
            $artifactResolveId,
            $now,
            self::status($o['outer_status'], null),
            $response,
        );

        $document = Xml::load($xml);
        $outer = self::find($document, Xml::SAMLP, 'ArtifactResponse');
        $inner = self::find($document, Xml::SAMLP, 'Response');

        if ($o['mutate'] instanceof Closure) {
            ($o['mutate'])($document);
        }

        if ($inner !== null && $o['sign_inner']) {
            XmlSignature::sign($inner, Keys::pair($o['inner_key']), true);
        }

        if ($outer !== null && $o['sign_outer']) {
            XmlSignature::sign($outer, Keys::pair($o['outer_key']));
        }

        if ($o['tamper'] instanceof Closure) {
            ($o['tamper'])($document);
        }

        return (string) $document->saveXML($document->documentElement);
    }

    /**
     * SOAP envelope with a signed LogoutResponse.
     *
     * @param list<string> $status
     */
    public static function logoutResponse(string $inResponseTo, array $status = [self::SUCCESS], string $key = 'idp'): string
    {
        $xml = sprintf(
            '<soap:Envelope xmlns:soap="%s"><soap:Body><saml2p:LogoutResponse xmlns:saml2p="%s" xmlns:saml2="%s" xmlns:ds="%s" ID="ID-lo-%s" InResponseTo="%s" IssueInstant="%s" Version="2.0">'
            . '<saml2:Issuer>login.gov.pl</saml2:Issuer>%s</saml2p:LogoutResponse></soap:Body></soap:Envelope>',
            Xml::SOAP,
            Xml::SAMLP,
            Xml::SAML,
            Xml::DS,
            bin2hex(random_bytes(6)),
            $inResponseTo,
            Xml::instant(CarbonImmutable::now()),
            self::status($status, null),
        );

        $document = Xml::load($xml);
        $element = self::find($document, Xml::SAMLP, 'LogoutResponse');

        if ($element !== null) {
            XmlSignature::sign($element, Keys::pair($key), true);
        }

        return (string) $document->saveXML($document->documentElement);
    }

    /**
     * Extracts the ID of the SAML request inside a SOAP envelope sent by the package.
     */
    public static function requestId(string $envelope): string
    {
        preg_match('/<saml2p:(?:ArtifactResolve|LogoutRequest)\b[^>]*\sID="([^"]+)"/', $envelope, $match);

        return $match[1] ?? '';
    }

    /**
     * @param list<string> $codes
     */
    private static function status(array $codes, ?string $message): string
    {
        $xml = '';

        foreach (array_reverse($codes) as $code) {
            $xml = $xml === ''
                ? sprintf('<saml2p:StatusCode Value="%s"/>', $code)
                : sprintf('<saml2p:StatusCode Value="%s">%s</saml2p:StatusCode>', $code, $xml);
        }

        return '<saml2p:Status>' . $xml . ($message !== null ? '<saml2p:StatusMessage>' . htmlspecialchars($message, ENT_XML1) . '</saml2p:StatusMessage>' : '') . '</saml2p:Status>';
    }

    private static function find(DOMDocument $document, string $namespace, string $localName): ?DOMElement
    {
        $node = $document->getElementsByTagNameNS($namespace, $localName)->item(0);

        return $node instanceof DOMElement ? $node : null;
    }

    private static function root(DOMDocument $document): DOMElement
    {
        $root = $document->documentElement;

        if ($root === null) {
            throw new \RuntimeException('Empty document.');
        }

        return $root;
    }
}
