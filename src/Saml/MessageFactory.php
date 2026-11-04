<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Saml;

use Beziworld\WezelKrajowy\Enums\LevelOfAssurance;
use Beziworld\WezelKrajowy\Enums\NameIdFormat;
use Beziworld\WezelKrajowy\Security\KeyPair;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\Security\XmlSignature;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;
use DateTimeInterface;

/**
 * Builds and signs the SAML messages a service provider sends to login.gov.pl.
 *
 * The element and attribute order follows the examples of the service
 * provider integration guide, because login.gov.pl validates the structure
 * strictly. Signatures reference the signed element by its ID.
 */
final class MessageFactory
{
    public const string HTTP_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact';

    private const string ATTRIBUTE_NAME_FORMAT = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';

    public function __construct(
        private readonly WezelKrajowyConfig $config,
        private readonly KeyPair $signingKey,
    ) {}

    /**
     * Signed AuthnRequest document (with XML declaration).
     */
    public function authnRequest(string $id, string $acsUrl, LevelOfAssurance $loa, DateTimeInterface $issueInstant): string
    {
        $attributes = '';

        foreach ($this->config->requestedAttributes() as $attribute) {
            $attributes .= sprintf(
                '<eidas:RequestedAttribute FriendlyName="%s" Name="%s" NameFormat="%s" isRequired="%s"/>',
                $attribute->name,
                $attribute->value,
                self::ATTRIBUTE_NAME_FORMAT,
                $attribute->isMandatory() ? 'true' : 'false',
            );
        }

        $providerName = $this->config->providerName !== null ? sprintf(' ProviderName="%s"', self::escape($this->config->providerName)) : '';

        $xml = sprintf(
            '<saml2p:AuthnRequest xmlns:saml2p="%s" xmlns:ds="%s" xmlns:eidas="%s" xmlns:naturalperson="%s" xmlns:saml2="%s" xmlns:xenc="%s"'
            . ' AssertionConsumerServiceURL="%s" Destination="%s" ForceAuthn="true" ID="%s" IssueInstant="%s" ProtocolBinding="%s"%s Version="2.0">'
            . '<saml2:Issuer>%s</saml2:Issuer>'
            . '<saml2p:Extensions><eidas:SPType>%s</eidas:SPType><eidas:RequestedAttributes>%s</eidas:RequestedAttributes></saml2p:Extensions>'
            . '<saml2p:NameIDPolicy AllowCreate="true" Format="%s"/>'
            . '<saml2p:RequestedAuthnContext Comparison="minimum"><saml2:AuthnContextClassRef>%s</saml2:AuthnContextClassRef></saml2p:RequestedAuthnContext>'
            . '</saml2p:AuthnRequest>',
            Xml::SAMLP,
            Xml::DS,
            Xml::EIDAS,
            Xml::NATURAL_PERSON,
            Xml::SAML,
            Xml::XENC,
            self::escape($acsUrl),
            self::escape($this->config->ssoUrl()),
            self::escape($id),
            Xml::instant($issueInstant),
            self::HTTP_ARTIFACT,
            $providerName,
            self::escape($this->config->entityId),
            $this->config->spType->value,
            $attributes,
            $this->config->nameIdFormat->value,
            $loa->value,
        );

        $document = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' . "\n" . $xml;

        return XmlSignature::signSerialized($document, Xml::SAMLP, 'AuthnRequest', $this->signingKey);
    }

    /**
     * Signed ArtifactResolve wrapped in a SOAP 1.1 envelope.
     */
    public function artifactResolve(string $id, string $artifact, DateTimeInterface $issueInstant): string
    {
        $xml = sprintf(
            '<saml2p:ArtifactResolve xmlns:saml2p="%s" xmlns:ds="%s" xmlns:saml2="%s" ID="%s" IssueInstant="%s" Version="2.0">'
            . '<saml2:Issuer>%s</saml2:Issuer><saml2p:Artifact>%s</saml2p:Artifact></saml2p:ArtifactResolve>',
            Xml::SAMLP,
            Xml::DS,
            Xml::SAML,
            self::escape($id),
            Xml::instant($issueInstant),
            self::escape($this->config->entityId),
            self::escape(trim($artifact)),
        );

        return $this->signEnvelope($xml, 'ArtifactResolve');
    }

    /**
     * Signed LogoutRequest wrapped in a SOAP 1.1 envelope.
     */
    public function logoutRequest(string $id, string $nameId, ?string $nameIdFormat, ?string $sessionIndex, DateTimeInterface $issueInstant): string
    {
        $format = $nameIdFormat ?? NameIdFormat::Unspecified->value;
        $session = $sessionIndex !== null ? sprintf('<saml2p:SessionIndex>%s</saml2p:SessionIndex>', self::escape($sessionIndex)) : '';

        $xml = sprintf(
            '<saml2p:LogoutRequest xmlns:saml2p="%s" xmlns:ds="%s" xmlns:saml2="%s" Destination="%s" ID="%s" IssueInstant="%s" Version="2.0">'
            . '<saml2:Issuer>%s</saml2:Issuer><saml2:NameID Format="%s">%s</saml2:NameID>%s</saml2p:LogoutRequest>',
            Xml::SAMLP,
            Xml::DS,
            Xml::SAML,
            self::escape($this->config->singleLogoutUrl()),
            self::escape($id),
            Xml::instant($issueInstant),
            self::escape($this->config->entityId),
            self::escape($format),
            self::escape($nameId),
            $session,
        );

        return $this->signEnvelope($xml, 'LogoutRequest');
    }

    public static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
    }

    private function signEnvelope(string $message, string $localName): string
    {
        $envelope = sprintf('<soap:Envelope xmlns:soap="%s"><soap:Header/><soap:Body>%s</soap:Body></soap:Envelope>', Xml::SOAP, $message);

        return XmlSignature::signSerialized($envelope, Xml::SAMLP, $localName, $this->signingKey);
    }
}
