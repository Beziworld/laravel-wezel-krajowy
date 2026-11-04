<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Saml;

use Beziworld\WezelKrajowy\Data\IdpMetadata;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Beziworld\WezelKrajowy\Security\Certificate;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;
use Carbon\CarbonImmutable;
use DOMElement;

/**
 * Parses identity provider metadata and builds service provider metadata.
 */
final class Metadata
{
    private const string ALGSUPPORT = 'urn:oasis:names:tc:SAML:metadata:algsupport';

    /**
     * @throws InvalidResponse
     */
    public static function parseIdp(string $xml): IdpMetadata
    {
        $document = Xml::load($xml);
        $root = $document->documentElement;

        if ($root === null || $root->namespaceURI !== Xml::MD || $root->localName !== 'EntityDescriptor') {
            throw InvalidResponse::because('the metadata is not a SAML EntityDescriptor');
        }

        $idp = Xml::child($root, Xml::MD, 'IDPSSODescriptor')
            ?? throw InvalidResponse::because('the metadata has no IDPSSODescriptor');

        $certificates = [];

        foreach (Xml::children($idp, Xml::MD, 'KeyDescriptor') as $descriptor) {
            $use = $descriptor->getAttribute('use');

            if ($use !== '' && $use !== 'signing') {
                continue;
            }

            $nodes = Xml::xpath($document)->query('./ds:KeyInfo/ds:X509Data/ds:X509Certificate', $descriptor);

            foreach ($nodes !== false ? $nodes : [] as $node) {
                $value = preg_replace('/\s+/', '', (string) $node->nodeValue);

                if (is_string($value) && $value !== '' && ! in_array($value, $certificates, true)) {
                    $certificates[] = $value;
                }
            }
        }

        $location = static function (string $element, string $binding) use ($idp): ?string {
            foreach (Xml::children($idp, Xml::MD, $element) as $service) {
                if ($service->getAttribute('Binding') === $binding) {
                    return Xml::attribute($service, 'Location');
                }
            }

            return null;
        };

        $attributes = [];

        foreach (Xml::children($idp, Xml::SAML, 'Attribute') as $attribute) {
            $name = Xml::attribute($attribute, 'Name');

            if ($name !== null) {
                $attributes[Xml::attribute($attribute, 'FriendlyName') ?? $name] = $name;
            }
        }

        $extensions = Xml::child($root, Xml::MD, 'Extensions');
        $methods = [];
        $spType = null;

        if ($extensions !== null) {
            foreach (Xml::children($extensions, self::ALGSUPPORT, 'SigningMethod') as $method) {
                $methods[] = $method->getAttribute('Algorithm');
            }

            $spType = Xml::text(Xml::child($extensions, Xml::EIDAS, 'SPType'));
        }

        $validUntil = Xml::attribute($root, 'validUntil');

        return new IdpMetadata(
            entityId: Xml::attribute($root, 'entityID') ?? '',
            validUntil: $validUntil !== null ? CarbonImmutable::parse($validUntil)->setTimezone('UTC') : null,
            ssoUrl: $location('SingleSignOnService', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
            artifactResolutionUrl: $location('ArtifactResolutionService', 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'),
            singleLogoutUrl: $location('SingleLogoutService', 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'),
            signingCertificates: $certificates,
            nameIdFormats: array_values(array_filter(
                array_map(static fn(DOMElement $format): ?string => Xml::text($format), Xml::children($idp, Xml::MD, 'NameIDFormat')),
                static fn(?string $format): bool => $format !== null,
            )),
            attributes: $attributes,
            signingMethods: $methods,
            spType: $spType,
        );
    }

    /**
     * Service provider metadata describing the signing and encryption
     * certificates and the HTTP-Artifact assertion consumer service.
     */
    public static function serviceProvider(WezelKrajowyConfig $config, string $acsUrl, ?Certificate $signing, ?Certificate $encryption): string
    {
        $keyDescriptor = static fn(string $use, Certificate $certificate): string => sprintf(
            '<md:KeyDescriptor use="%s"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>',
            $use,
            $certificate->base64(),
        );

        $keys = ($signing !== null ? $keyDescriptor('signing', $signing) : '')
            . ($encryption !== null ? $keyDescriptor('encryption', $encryption) : '');

        $xml = sprintf(
            '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
            . '<md:EntityDescriptor xmlns:md="%s" xmlns:ds="%s" xmlns:eidas="%s" entityID="%s">'
            . '<md:Extensions><eidas:SPType>%s</eidas:SPType></md:Extensions>'
            . '<md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            . '%s<md:NameIDFormat>%s</md:NameIDFormat>'
            . '<md:AssertionConsumerService Binding="%s" Location="%s" index="0" isDefault="true"/>'
            . '</md:SPSSODescriptor></md:EntityDescriptor>',
            Xml::MD,
            Xml::DS,
            Xml::EIDAS,
            MessageFactory::escape($config->entityId),
            $config->spType->value,
            $keys,
            $config->nameIdFormat->value,
            MessageFactory::HTTP_ARTIFACT,
            MessageFactory::escape($acsUrl),
        );

        $document = Xml::load($xml);
        $document->formatOutput = true;

        return (string) $document->saveXML();
    }
}
