<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Security;

use Beziworld\WezelKrajowy\Exceptions\InvalidSignature;
use DOMDocument;
use DOMElement;
use DOMNode;

/**
 * Enveloped XML Signature in the shape required by login.gov.pl.
 *
 * Verification is deliberately narrow: exactly one Signature child of the
 * signed element, exactly one Reference pointing at that same element
 * (URI="" or URI="#ID"), the enveloped transform plus one canonicalization,
 * and SHA-2 digests only. Callers read data exclusively from the element
 * that was verified, which rules out signature wrapping.
 */
final class XmlSignature
{
    private const string PLACEHOLDER = '__WEZEL_KRAJOWY_SIGNATURE_VALUE__';

    /**
     * Signs the first element with the given name in a serialized document
     * and returns the signed document.
     *
     * The Signature is spliced into the serialized text right after the
     * Issuer end tag, so the output keeps the exact byte layout of the input
     * and the Signature has the form shown in the login.gov.pl integration
     * guide (InclusiveNamespaces in the default namespace, no whitespace).
     *
     * @param bool $emptyReference Use URI="" instead of URI="#ID".
     */
    public static function signSerialized(string $xml, string $namespace, string $localName, KeyPair $key, bool $emptyReference = false): string
    {
        $document = new DOMDocument();
        $document->loadXML($xml, LIBXML_NONET);
        $element = $document->getElementsByTagNameNS($namespace, $localName)->item(0);
        $issuer = $element instanceof DOMElement ? Xml::child($element, Xml::SAML, 'Issuer') : null;

        if (! $element instanceof DOMElement || $issuer === null) {
            throw InvalidSignature::because($localName, 'the element to sign or its Issuer was not found');
        }

        $id = $element->getAttribute('ID');
        $digest = base64_encode(hash('sha256', self::canonicalize($element, Algorithm::EXC_C14N, Algorithm::INCLUSIVE_PREFIXES), true));
        $certificate = $key->certificate();

        $signature = sprintf(
            '<ds:Signature%s><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="%s"/><ds:SignatureMethod Algorithm="%s"/>'
            . '<ds:Reference URI="%s"><ds:Transforms><ds:Transform Algorithm="%s"/><ds:Transform Algorithm="%s">'
            . '<InclusiveNamespaces xmlns="%s" PrefixList="%s"/></ds:Transform></ds:Transforms>'
            . '<ds:DigestMethod Algorithm="%s"/><ds:DigestValue>%s</ds:DigestValue></ds:Reference></ds:SignedInfo>'
            . '<ds:SignatureValue>%s</ds:SignatureValue>%s</ds:Signature>',
            $element->lookupNamespaceURI('ds') === Xml::DS ? '' : ' xmlns:ds="' . Xml::DS . '"',
            Algorithm::EXC_C14N,
            $key->signatureMethod(),
            $emptyReference || $id === '' ? '' : '#' . htmlspecialchars($id, ENT_QUOTES | ENT_XML1),
            Algorithm::ENVELOPED_SIGNATURE,
            Algorithm::EXC_C14N,
            Xml::EXC_C14N,
            implode(' ', Algorithm::INCLUSIVE_PREFIXES),
            Algorithm::SHA256,
            $digest,
            self::PLACEHOLDER,
            $certificate !== null ? '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' . $certificate->base64() . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' : '',
        );

        $start = strpos($xml, '<' . $element->nodeName);
        $closing = '</' . $issuer->nodeName . '>';
        $position = $start !== false ? strpos($xml, $closing, $start) : false;

        if ($position === false) {
            throw InvalidSignature::because($localName, 'the Issuer end tag was not found in the serialized document');
        }

        $signed = substr_replace($xml, $signature, $position + strlen($closing), 0);

        $check = new DOMDocument();
        $check->loadXML($signed, LIBXML_NONET);
        $signedInfo = $check->getElementsByTagNameNS(Xml::DS, 'SignedInfo')->item(0);

        if (! $signedInfo instanceof DOMElement) {
            throw InvalidSignature::because($localName, 'the inserted SignedInfo was not found');
        }

        $value = base64_encode($key->sign(self::canonicalize($signedInfo, Algorithm::EXC_C14N, null)));

        return str_replace(self::PLACEHOLDER, $value, $signed);
    }

    /**
     * Signs an element in place and inserts the Signature after the Issuer child.
     *
     * The DOM extension cannot keep a default namespace declaration inside a
     * prefixed tree, so InclusiveNamespaces uses the conventional "ec" prefix
     * here; both forms are equivalent for every XML Signature processor.
     *
     * @param bool $emptyReference Use URI="" instead of URI="#ID".
     */
    public static function sign(DOMElement $element, KeyPair $key, bool $emptyReference = false): void
    {
        $document = self::document($element);
        $id = $element->getAttribute('ID');
        $uri = $emptyReference || $id === '' ? '' : '#' . $id;

        $digest = base64_encode(hash('sha256', self::canonicalize($element, Algorithm::EXC_C14N, Algorithm::INCLUSIVE_PREFIXES), true));

        $signature = $document->createElementNS(Xml::DS, 'ds:Signature');
        $signedInfo = $document->createElementNS(Xml::DS, 'ds:SignedInfo');
        $signature->appendChild($signedInfo);

        $c14n = $document->createElementNS(Xml::DS, 'ds:CanonicalizationMethod');
        $c14n->setAttribute('Algorithm', Algorithm::EXC_C14N);
        $signedInfo->appendChild($c14n);

        $method = $document->createElementNS(Xml::DS, 'ds:SignatureMethod');
        $method->setAttribute('Algorithm', $key->signatureMethod());
        $signedInfo->appendChild($method);

        $reference = $document->createElementNS(Xml::DS, 'ds:Reference');
        $reference->setAttribute('URI', $uri);
        $signedInfo->appendChild($reference);

        $transforms = $document->createElementNS(Xml::DS, 'ds:Transforms');
        $reference->appendChild($transforms);

        $enveloped = $document->createElementNS(Xml::DS, 'ds:Transform');
        $enveloped->setAttribute('Algorithm', Algorithm::ENVELOPED_SIGNATURE);
        $transforms->appendChild($enveloped);

        $exclusive = $document->createElementNS(Xml::DS, 'ds:Transform');
        $exclusive->setAttribute('Algorithm', Algorithm::EXC_C14N);
        $inclusive = $document->createElementNS(Xml::EXC_C14N, 'ec:InclusiveNamespaces');
        $inclusive->setAttribute('PrefixList', implode(' ', Algorithm::INCLUSIVE_PREFIXES));
        $exclusive->appendChild($inclusive);
        $transforms->appendChild($exclusive);

        $digestMethod = $document->createElementNS(Xml::DS, 'ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', Algorithm::SHA256);
        $reference->appendChild($digestMethod);
        $reference->appendChild($document->createElementNS(Xml::DS, 'ds:DigestValue', $digest));

        $signatureValue = $document->createElementNS(Xml::DS, 'ds:SignatureValue');
        $signature->appendChild($signatureValue);

        $certificate = $key->certificate();

        if ($certificate !== null) {
            $keyInfo = $document->createElementNS(Xml::DS, 'ds:KeyInfo');
            $x509Data = $document->createElementNS(Xml::DS, 'ds:X509Data');
            $x509Data->appendChild($document->createElementNS(Xml::DS, 'ds:X509Certificate', $certificate->base64()));
            $keyInfo->appendChild($x509Data);
            $signature->appendChild($keyInfo);
        }

        $issuer = Xml::child($element, Xml::SAML, 'Issuer');
        $anchor = $issuer !== null ? $issuer->nextSibling : $element->firstChild;
        $anchor !== null ? $element->insertBefore($signature, $anchor) : $element->appendChild($signature);

        $signatureValue->textContent = base64_encode($key->sign(self::canonicalize($signedInfo, Algorithm::EXC_C14N, null)));
    }

    public static function isSigned(DOMElement $element): bool
    {
        return Xml::children($element, Xml::DS, 'Signature') !== [];
    }

    /**
     * Verifies the enveloped signature of an element and returns the
     * trusted certificate that validated it.
     *
     * @param list<Certificate> $trusted
     *
     * @throws InvalidSignature
     */
    public static function verify(DOMElement $element, array $trusted): Certificate
    {
        $name = $element->localName ?? 'element';
        $signatures = Xml::children($element, Xml::DS, 'Signature');

        if (count($signatures) !== 1) {
            throw InvalidSignature::because($name, $signatures === [] ? 'the element is not signed' : 'more than one signature');
        }

        if ($trusted === []) {
            throw InvalidSignature::because($name, 'no trusted login.gov.pl certificate is configured');
        }

        $signature = $signatures[0];
        $signedInfo = self::one($signature, 'SignedInfo', $name);
        $c14nMethod = self::one($signedInfo, 'CanonicalizationMethod', $name)->getAttribute('Algorithm');

        if (! in_array($c14nMethod, Algorithm::CANONICALIZATION_METHODS, true)) {
            throw InvalidSignature::because($name, 'unsupported canonicalization method ' . $c14nMethod);
        }

        $signatureMethod = self::one($signedInfo, 'SignatureMethod', $name)->getAttribute('Algorithm');
        $method = Algorithm::SIGNATURE_METHODS[$signatureMethod] ?? null;

        if ($method === null) {
            throw InvalidSignature::because($name, 'unsupported or forbidden signature method ' . $signatureMethod);
        }

        $references = Xml::children($signedInfo, Xml::DS, 'Reference');

        if (count($references) !== 1) {
            throw InvalidSignature::because($name, 'exactly one Reference is required');
        }

        $reference = $references[0];
        $uri = $reference->getAttribute('URI');
        $id = $element->getAttribute('ID');

        if ($uri !== '' && ($id === '' || $uri !== '#' . $id)) {
            throw InvalidSignature::because($name, 'the Reference does not point at the signed element');
        }

        [$transformC14n, $prefixes] = self::transforms($reference, $name);

        $digestMethod = self::one($reference, 'DigestMethod', $name)->getAttribute('Algorithm');
        $hash = Algorithm::DIGEST_METHODS[$digestMethod] ?? null;

        if ($hash === null) {
            throw InvalidSignature::because($name, 'unsupported or forbidden digest method ' . $digestMethod);
        }

        $expected = base64_decode((string) preg_replace('/\s+/', '', self::one($reference, 'DigestValue', $name)->textContent), true);
        $actual = hash($hash, self::canonicalizeWithout($element, $signature, $transformC14n, $prefixes), true);

        if ($expected === false || ! hash_equals($expected, $actual)) {
            throw InvalidSignature::because($name, 'digest mismatch, the content was modified');
        }

        $value = base64_decode((string) preg_replace('/\s+/', '', self::one($signature, 'SignatureValue', $name)->textContent), true);

        if ($value === false || $value === '') {
            throw InvalidSignature::because($name, 'empty SignatureValue');
        }

        $signedInfoPrefixes = self::inclusivePrefixes(self::one($signedInfo, 'CanonicalizationMethod', $name));
        $canonicalSignedInfo = self::canonicalize($signedInfo, $c14nMethod, $signedInfoPrefixes);

        foreach ($trusted as $certificate) {
            if ($certificate->verify($canonicalSignedInfo, $value, $method[0], $method[1])) {
                return $certificate;
            }
        }

        throw InvalidSignature::because($name, 'the signature does not match any trusted login.gov.pl certificate');
    }

    /**
     * @param list<string>|null $prefixes
     */
    public static function canonicalize(DOMNode $node, string $method, ?array $prefixes): string
    {
        $exclusive = str_starts_with($method, Algorithm::EXC_C14N);
        $comments = str_ends_with($method, '#WithComments');
        $result = $node->C14N($exclusive, $comments, null, $exclusive ? $prefixes : null);

        if ($result === false) {
            throw InvalidSignature::because($node->nodeName, 'canonicalization failed');
        }

        return $result;
    }

    /**
     * Canonicalizes an element without the given Signature subtree (the
     * enveloped-signature transform), keeping the ancestor namespace context.
     *
     * The Signature is excluded through an XPath node set instead of being
     * detached, because re-attaching nodes makes the DOM extension rewrite
     * default namespace declarations inside the Signature.
     *
     * @param list<string>|null $prefixes
     */
    private static function canonicalizeWithout(DOMElement $element, DOMElement $signature, string $method, ?array $prefixes): string
    {
        $marker = 'wezel-krajowy-enveloped-' . bin2hex(random_bytes(4));
        $signature->setAttribute($marker, '1');

        try {
            $exclusive = str_starts_with($method, Algorithm::EXC_C14N);
            $result = $element->C14N(
                $exclusive,
                str_ends_with($method, '#WithComments'),
                [
                    'query' => sprintf('(.//. | .//@* | .//namespace::*)[not(ancestor-or-self::ds:Signature[@%s])]', $marker),
                    'namespaces' => ['ds' => Xml::DS],
                ],
                $exclusive ? $prefixes : null,
            );
        } finally {
            $signature->removeAttribute($marker);
        }

        if ($result === false) {
            throw InvalidSignature::because($element->nodeName, 'canonicalization failed');
        }

        return $result;
    }

    /**
     * @return array{0: string, 1: list<string>|null}
     */
    private static function transforms(DOMElement $reference, string $name): array
    {
        $transforms = Xml::child($reference, Xml::DS, 'Transforms');
        $enveloped = false;
        $c14n = Algorithm::C14N;
        $prefixes = null;
        $c14nCount = 0;

        foreach ($transforms !== null ? Xml::children($transforms, Xml::DS, 'Transform') : [] as $transform) {
            $algorithm = $transform->getAttribute('Algorithm');

            if ($algorithm === Algorithm::ENVELOPED_SIGNATURE) {
                $enveloped = true;
            } elseif (in_array($algorithm, Algorithm::CANONICALIZATION_METHODS, true)) {
                $c14n = $algorithm;
                $prefixes = self::inclusivePrefixes($transform);
                $c14nCount++;
            } else {
                throw InvalidSignature::because($name, 'unsupported transform ' . $algorithm);
            }
        }

        if (! $enveloped || $c14nCount > 1) {
            throw InvalidSignature::because($name, 'the Reference must use the enveloped-signature transform and at most one canonicalization');
        }

        return [$c14n, $prefixes];
    }

    /**
     * @return list<string>|null
     */
    private static function inclusivePrefixes(DOMElement $parent): ?array
    {
        $inclusive = Xml::child($parent, Xml::EXC_C14N, 'InclusiveNamespaces');

        if ($inclusive === null) {
            return null;
        }

        $list = preg_split('/\s+/', trim($inclusive->getAttribute('PrefixList')));

        if ($list === false) {
            return null;
        }

        return array_values(array_filter($list, static fn(string $prefix): bool => $prefix !== ''));
    }

    private static function one(DOMElement $parent, string $localName, string $name): DOMElement
    {
        $children = Xml::children($parent, Xml::DS, $localName);

        if (count($children) !== 1) {
            throw InvalidSignature::because($name, sprintf('expected exactly one ds:%s', $localName));
        }

        return $children[0];
    }

    private static function document(DOMElement $element): DOMDocument
    {
        $document = $element->ownerDocument;

        if ($document === null) {
            throw InvalidSignature::because($element->nodeName, 'the element does not belong to a document');
        }

        return $document;
    }
}
