<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Data;

/**
 * Signed AuthnRequest ready to be POSTed by the browser to login.gov.pl.
 */
final readonly class AuthnRequestMessage
{
    /**
     * @param array<string, string> $fields Hidden form fields (SAMLRequest and optional extras).
     */
    public function __construct(
        public PendingRequest $request,
        public string $destination,
        public string $xml,
        public array $fields,
    ) {}

    /**
     * Self-submitting HTML form, with a manual button when JavaScript is disabled.
     */
    public function toHtml(): string
    {
        $escape = static fn(string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $inputs = '';

        foreach ($this->fields as $name => $value) {
            $inputs .= sprintf('<input type="hidden" name="%s" value="%s">', $escape($name), $escape($value));
        }

        return '<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"><meta name="robots" content="noindex">'
            . '<title>login.gov.pl</title></head><body onload="document.forms[0].submit()">'
            . sprintf('<form method="post" action="%s">%s', $escape($this->destination), $inputs)
            . '<noscript><p>JavaScript jest wyłączony. Aby kontynuować logowanie, naciśnij przycisk.</p>'
            . '<button type="submit">Kontynuuj</button></noscript></form></body></html>';
    }
}
