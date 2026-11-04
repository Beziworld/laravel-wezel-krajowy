<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Security;

use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Carbon\CarbonImmutable;
use DateTimeInterface;
use DateTimeZone;
use DOMDocument;
use DOMDocumentType;
use DOMElement;
use DOMNode;
use DOMXPath;
use Illuminate\Support\Str;
use Throwable;

/**
 * Namespace constants and hardened DOM helpers.
 */
final class Xml
{
    public const string SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

    public const string SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

    public const string MD = 'urn:oasis:names:tc:SAML:2.0:metadata';

    public const string DS = 'http://www.w3.org/2000/09/xmldsig#';

    public const string DSIG11 = 'http://www.w3.org/2009/xmldsig11#';

    public const string XENC = 'http://www.w3.org/2001/04/xmlenc#';

    public const string XENC11 = 'http://www.w3.org/2009/xmlenc11#';

    public const string EIDAS = 'http://eidas.europa.eu/saml-extensions';

    public const string NATURAL_PERSON = 'http://eidas.europa.eu/attributes/naturalperson';

    public const string SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';

    public const string XSI = 'http://www.w3.org/2001/XMLSchema-instance';

    public const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    public const string EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    /**
     * Prefixes registered on every XPath instance.
     *
     * @var array<string, string>
     */
    public const array PREFIXES = [
        'saml2p' => self::SAMLP,
        'saml2' => self::SAML,
        'md' => self::MD,
        'ds' => self::DS,
        'dsig11' => self::DSIG11,
        'xenc' => self::XENC,
        'xenc11' => self::XENC11,
        'eidas' => self::EIDAS,
        'naturalperson' => self::NATURAL_PERSON,
        'soap' => self::SOAP,
        'ec' => self::EXC_C14N,
    ];

    /**
     * Parses untrusted XML without network access, entity expansion or DTDs.
     *
     * @throws InvalidResponse
     */
    public static function load(string $xml): DOMDocument
    {
        $xml = trim($xml);

        if ($xml === '') {
            throw InvalidResponse::because('the XML document is empty');
        }

        if (stripos($xml, '<!DOCTYPE') !== false || stripos($xml, '<!ENTITY') !== false) {
            throw InvalidResponse::because('XML documents with a DOCTYPE are not accepted');
        }

        $previous = libxml_use_internal_errors(true);
        $document = new DOMDocument('1.0', 'UTF-8');
        $document->preserveWhiteSpace = true;

        try {
            $loaded = $document->loadXML($xml, LIBXML_NONET);
            $errors = libxml_get_errors();
        } catch (Throwable) {
            $loaded = false;
            $errors = [];
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }

        if ($loaded === false || $document->documentElement === null) {
            $detail = $errors !== [] ? trim($errors[0]->message) : 'parse error';

            throw InvalidResponse::because('the XML document is not well formed (' . $detail . ')');
        }

        foreach ($document->childNodes as $child) {
            if ($child instanceof DOMDocumentType) {
                throw InvalidResponse::because('XML documents with a DOCTYPE are not accepted');
            }
        }

        return $document;
    }

    public static function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);

        foreach (self::PREFIXES as $prefix => $namespace) {
            $xpath->registerNamespace($prefix, $namespace);
        }

        return $xpath;
    }

    /**
     * Returns the direct child elements with the given namespace and local name.
     *
     * @return list<DOMElement>
     */
    public static function children(DOMNode $parent, string $namespace, string $localName): array
    {
        $found = [];

        foreach ($parent->childNodes as $child) {
            if ($child instanceof DOMElement && ($child->namespaceURI ?? '') === $namespace && $child->localName === $localName) {
                $found[] = $child;
            }
        }

        return $found;
    }

    public static function child(DOMNode $parent, string $namespace, string $localName): ?DOMElement
    {
        return self::children($parent, $namespace, $localName)[0] ?? null;
    }

    /**
     * Returns exactly one direct child or fails with a descriptive message.
     *
     * @throws InvalidResponse
     */
    public static function single(DOMNode $parent, string $namespace, string $localName): DOMElement
    {
        $children = self::children($parent, $namespace, $localName);

        if (count($children) !== 1) {
            throw InvalidResponse::because(sprintf('expected exactly one <%s> element, found %d', $localName, count($children)));
        }

        return $children[0];
    }

    public static function text(?DOMElement $element): ?string
    {
        if ($element === null) {
            return null;
        }

        $value = trim($element->textContent);

        return $value === '' ? null : $value;
    }

    public static function attribute(DOMElement $element, string $name): ?string
    {
        if (! $element->hasAttribute($name)) {
            return null;
        }

        $value = trim($element->getAttribute($name));

        return $value === '' ? null : $value;
    }

    /**
     * Formats an instant as an xs:dateTime in UTC with milliseconds.
     */
    public static function instant(DateTimeInterface $time): string
    {
        return CarbonImmutable::instance($time)->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.v\Z');
    }

    /**
     * @throws InvalidResponse
     */
    public static function parseInstant(?string $value, string $attribute): CarbonImmutable
    {
        if ($value === null || preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/', $value) !== 1) {
            throw InvalidResponse::because(sprintf('%s is missing or is not a valid xs:dateTime', $attribute));
        }

        return CarbonImmutable::parse($value)->setTimezone('UTC');
    }

    /**
     * Generates a SAML identifier; it starts with a letter as xs:ID requires.
     */
    public static function newId(): string
    {
        return 'ID-' . Str::uuid()->toString();
    }

    /**
     * Declares a namespace prefix on an element.
     */
    public static function declare(DOMElement $element, string $prefix, string $namespace): void
    {
        $element->setAttributeNS(self::XMLNS, 'xmlns:' . $prefix, $namespace);
    }
}
