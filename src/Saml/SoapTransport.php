<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Saml;

use Beziworld\WezelKrajowy\Exceptions\ApiException;
use Beziworld\WezelKrajowy\Exceptions\InvalidResponse;
use Beziworld\WezelKrajowy\Security\Xml;
use Beziworld\WezelKrajowy\WezelKrajowyConfig;
use DOMElement;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;

/**
 * SAML SOAP binding over HTTP for the login.gov.pl back channel.
 *
 * Requests are never retried: an artifact can be resolved only once and a
 * logout must not be repeated blindly.
 */
final class SoapTransport
{
    public const string SOAP_ACTION = 'http://www.oasis-open.org/committees/security';

    public function __construct(
        private readonly HttpFactory $http,
        private readonly WezelKrajowyConfig $config,
    ) {}

    /**
     * Posts an envelope and returns the first element of the response Body.
     *
     * @throws ApiException
     */
    public function send(string $endpoint, string $envelope): DOMElement
    {
        try {
            $response = $this->http->createPendingRequest()
                ->withHeaders([
                    'Content-Type' => 'text/xml; charset=utf-8',
                    'Accept' => 'text/xml, application/soap+xml',
                    'SOAPAction' => '"' . self::SOAP_ACTION . '"',
                ])
                ->timeout($this->config->timeout)
                ->connectTimeout($this->config->connectTimeout)
                ->withBody($envelope, 'text/xml; charset=utf-8')
                ->post($endpoint);
        } catch (ConnectionException $exception) {
            throw ApiException::transport($endpoint, $exception);
        }

        $body = $response->body();

        if ($response->failed()) {
            throw ApiException::http($endpoint, $response->status(), $this->faultString($body));
        }

        try {
            $document = Xml::load($body);
        } catch (InvalidResponse) {
            throw ApiException::invalidResponse($endpoint, 'the body is not XML');
        }

        $root = $document->documentElement;
        $soapBody = $root !== null && $root->namespaceURI === Xml::SOAP && $root->localName === 'Envelope'
            ? Xml::child($root, Xml::SOAP, 'Body')
            : null;

        if ($soapBody === null) {
            throw ApiException::invalidResponse($endpoint, 'missing SOAP Envelope/Body');
        }

        $fault = Xml::child($soapBody, Xml::SOAP, 'Fault');

        if ($fault !== null) {
            throw ApiException::http($endpoint, $response->status(), Xml::text(Xml::child($fault, '', 'faultstring')) ?? Xml::text($fault));
        }

        foreach ($soapBody->childNodes as $child) {
            if ($child instanceof DOMElement) {
                return $child;
            }
        }

        throw ApiException::invalidResponse($endpoint, 'empty SOAP Body');
    }

    private function faultString(string $body): ?string
    {
        if (preg_match('/<(?:\w+:)?faultstring[^>]*>(.*?)<\/(?:\w+:)?faultstring>/s', $body, $match) === 1) {
            $text = trim(html_entity_decode(strip_tags($match[1]), ENT_QUOTES | ENT_XML1, 'UTF-8'));

            return $text !== '' ? mb_substr($text, 0, 300) : null;
        }

        return null;
    }
}
