# Laravel Węzeł Krajowy (login.gov.pl)

[![tests](https://github.com/beziworld/laravel-wezel-krajowy/actions/workflows/tests.yml/badge.svg)](https://github.com/beziworld/laravel-wezel-krajowy/actions/workflows/tests.yml)
[![Latest Version](https://img.shields.io/packagist/v/beziworld/laravel-wezel-krajowy.svg)](https://packagist.org/packages/beziworld/laravel-wezel-krajowy)
[![License](https://img.shields.io/packagist/l/beziworld/laravel-wezel-krajowy.svg)](LICENSE.md)

Log users in to a Laravel application with the Polish **National Electronic Identification Node**
(Węzeł Krajowy Identyfikacji Elektronicznej, [login.gov.pl](https://login.gov.pl)): Profil Zaufany, mObywatel,
e-dowód (personal ID card) and bank identities, through one integration.

- SAML 2.0 service provider for the login.gov.pl profile: signed `AuthnRequest` over HTTP-POST, **HTTP-Artifact**
  response binding, `ArtifactResolve` over the SOAP back channel, signed SOAP single logout (`LogoutRequest`)
- ECDSA P-256 (and RSA-SHA256) XML signatures, assertion decryption with **ECDH-ES + ConcatKDF + AES-256 key wrap +
  AES-GCM** as login.gov.pl uses it, RSA-OAEP key transport for RSA encryption certificates
- strict validation: signatures of every layer against pinned certificates, `InResponseTo`, one-time requests, assertion
  replay cache, `NotBefore` / `NotOnOrAfter` with clock skew, audience, recipient, destination, eIDAS level of assurance,
  mandatory attributes
- ready routes (login, assertion consumer, logout, service provider metadata), `UserAuthenticated` event with a typed
  `Identity` (first name, family name, date of birth, PESEL, level of assurance, identity provider), a user resolver
  hook that logs the user in, `wezel-krajowy.loa:high` middleware
- integration (`int.login.gov.pl`), production for public entities (`login.gov.pl`) and production for private
  entities (`podmiotyzewnetrzne.login.gov.pl`), with endpoint overrides for simulators
- `wezel-krajowy:metadata` and `wezel-krajowy:idp-metadata` Artisan commands

[Polska wersja dokumentacji](README.pl.md)

## Why this package

At the time of writing Packagist has no package for login.gov.pl, Profil Zaufany or Węzeł Krajowy (searches for
"profil zaufany", "wezel krajowy", "login-gov-pl" return nothing; "epuap" returns two old ePUAP libraries that predate
the node). The general PHP SAML libraries do not fit the profile: `onelogin/php-saml` has no HTTP-Artifact binding and
no ECDSA, and `robrichards/xmlseclibs` signs with RSA/HMAC only and has no ECDH-ES, ConcatKDF or AES key wrap. This
package therefore implements the narrow XML Signature / XML Encryption subset that login.gov.pl uses, on top of
`ext-dom` canonicalization, [phpseclib 3](https://phpseclib.com) (ECDSA, ECDH, RSA, X.509) and `ext-openssl`
(AES-GCM, AES for RFC 3394 key wrap). The verifier was checked against the real ECDSA signatures in the public
metadata of all three login.gov.pl environments.

## Before you start

Access is granted by the Ministry of Digital Affairs, not by self-service:

1. Apply for the integration environment on [wspolpraca.ct.gov.pl](https://wspolpraca.ct.gov.pl) (portal
   "Współpraca Cyfrowa Tożsamość"). COI sends the test certificates, the Issuer value, passwords and test scenarios.
2. Register your SAML Issuer, the assertion consumer URL (`https://your-app/wezel-krajowy/acs`) and the IP addresses
   that call login.gov.pl. Access is activated with the first correctly signed `AuthnRequest`.
3. After the tests, apply for production. Production needs two certificates bought from a qualified trust service
   provider: one for signing (ECDSA P-256 or RSA-SHA256, Digital Signature usage) and one for decryption (Key
   Agreement usage). login.gov.pl requires separate keys for signing and decryption.

## Installation

```bash
composer require beziworld/laravel-wezel-krajowy
php artisan vendor:publish --tag=wezel-krajowy-config   # optional
```

```dotenv
WEZEL_KRAJOWY_ENV=integration                 # integration | production | production-private
WEZEL_KRAJOWY_ISSUER=https://your-app.pl      # SAML Issuer registered with COI
WEZEL_KRAJOWY_PROVIDER_NAME=your-app          # ProviderName agreed with COI
WEZEL_KRAJOWY_SP_TYPE=public                  # public | private (eIDAS SPType)

WEZEL_KRAJOWY_SIGNING_KEY=/secure/wk-sign.key        # path or inline PEM (EC P-256 or RSA)
WEZEL_KRAJOWY_SIGNING_CERTIFICATE=/secure/wk-sign.crt
WEZEL_KRAJOWY_SIGNING_PASSPHRASE=
WEZEL_KRAJOWY_ENCRYPTION_KEY=/secure/wk-enc.key
WEZEL_KRAJOWY_ENCRYPTION_CERTIFICATE=/secure/wk-enc.crt
WEZEL_KRAJOWY_ENCRYPTION_PASSPHRASE=

# Pin the login.gov.pl signing certificates (recommended) ...
WEZEL_KRAJOWY_IDP_CERTIFICATES=/secure/login-gov-pl-ec.pem,/secure/login-gov-pl-rsa.pem
# ... or read them from the public metadata of the environment over HTTPS:
WEZEL_KRAJOWY_TRUST_METADATA=false

WEZEL_KRAJOWY_LOA=substantial                 # low | substantial | high
WEZEL_KRAJOWY_CACHE_STORE=                    # shared cache store for pending requests
```

Get the current login.gov.pl certificates for pinning:

```bash
php artisan wezel-krajowy:idp-metadata --save=storage/app/wezel-krajowy
```

Keep private keys outside the repository and the web root, readable only by the PHP user (for example
`chmod 600`, owned by the web server account), and prefer files over inline PEM in `.env`. The session holds the
verified identity including the PESEL, so enable `SESSION_ENCRYPT=true` and use a server-side session driver. Once the
Issuer that login.gov.pl uses in your environment is known, set `WEZEL_KRAJOWY_IDP_ENTITY_ID` to enforce it. Consider
adding `throttle` to `routes.middleware`, because every visit of the login route stores a pending request in the cache.

## Logging in

The package registers these routes (prefix and middleware are configurable):

| Method | URI | Name | Purpose |
| --- | --- | --- | --- |
| GET | `/wezel-krajowy/login?return_to=/orders&loa=high` | `wezel-krajowy.login` | signs an `AuthnRequest` and auto-posts it to login.gov.pl |
| POST | `/wezel-krajowy/acs` | `wezel-krajowy.acs.post` | receives `SAMLart` from the browser and redirects (303) to the GET variant |
| GET | `/wezel-krajowy/acs` | `wezel-krajowy.acs` | resolves the artifact, validates the assertion, logs the user in |
| POST | `/wezel-krajowy/logout` | `wezel-krajowy.logout` | single logout at login.gov.pl, then local logout |
| GET | `/wezel-krajowy/metadata` | `wezel-krajowy.metadata` | service provider metadata |

The browser returns from login.gov.pl with a cross-site POST, which carries no `SameSite=Lax` session cookie and no
CSRF token. The POST route has no middleware and only answers with a 303 redirect to the GET route, where the session
is available. Pending requests live in the cache, so they survive that hop.

```blade
<a href="{{ route('wezel-krajowy.login', ['return_to' => '/orders']) }}">Zaloguj przez login.gov.pl</a>

<form method="post" action="{{ route('wezel-krajowy.logout') }}">@csrf <button>Wyloguj</button></form>

@if (session('wezel_krajowy_error'))
    <p>Logowanie nie powiodło się ({{ session('wezel_krajowy_error') }}).</p>
@endif
```

Map the identity to a user. The package logs the returned user in through the configured guard and regenerates the
session; returning `null` refuses the login:

```php
use Beziworld\WezelKrajowy\Data\Identity;
use Beziworld\WezelKrajowy\Facades\WezelKrajowy;

// AppServiceProvider::boot()
WezelKrajowy::resolveUsersUsing(function (Identity $identity) {
    return User::where('pesel', $identity->pesel)->first();
});
```

Or implement `Beziworld\WezelKrajowy\Contracts\IdentityResolver` and set `auth.resolver` in the config. Without a
resolver the identity is stored in the session and announced with the event, so the application can handle the login
itself.

## Identity

```php
use Beziworld\WezelKrajowy\Events\UserAuthenticated;

Event::listen(function (UserAuthenticated $event) {
    $identity = $event->identity;

    $identity->firstName;          // "Jan"
    $identity->familyName;         // "Niezbędny"
    $identity->dateOfBirth;        // CarbonImmutable 1986-07-25, Europe/Warsaw
    $identity->pesel;              // "86072500004" (null for foreign eIDAS identities)
    $identity->personIdentifier;   // raw eIDAS PersonIdentifier
    $identity->levelOfAssurance;   // LevelOfAssurance::Substantial
    $identity->identityProvider;   // "pz.gov.pl" (AuthenticatingAuthority)
    $identity->nameId;             // NameID used for single logout
    $identity->sessionIndex;
    $identity->attribute('BirthName');   // optional attributes when requested
    $event->user;                  // the logged-in user, or null without a resolver
});

WezelKrajowy::identity();          // identity of the current session
```

Optional attributes (BirthName, PlaceOfBirth, CurrentAddress, Gender, and the others published in the metadata) are
requested with `authn.attributes`; whether an identity provider delivers them is not guaranteed.

## Level of assurance

`WEZEL_KRAJOWY_LOA` is the minimum for every login. A route can require more:

```php
Route::middleware('wezel-krajowy.loa:high')->get('/sign', SignController::class);
```

Users below the level are sent through the login again with `loa=high`; JSON requests receive 401. A response whose
`AuthnContextClassRef` is lower than requested is rejected.

## Using the service directly

```php
$response = WezelKrajowy::redirect('/orders', LevelOfAssurance::High);  // HTML auto-post form
$message  = WezelKrajowy::authnRequest('/orders');                      // signed XML + form fields
$result   = WezelKrajowy::resolveArtifact($request->query('SAMLart'), $request);  // AuthenticationResult
$logout   = WezelKrajowy::logoutIdentity($identity);                    // LogoutResult: successful(), partial()
$xml      = WezelKrajowy::serviceProviderMetadata();
$idp      = WezelKrajowy::identityProviderMetadata();                   // endpoints, certificates
```

## Security checks

| Check | Failure |
| --- | --- |
| `ArtifactResponse` signed by a trusted login.gov.pl certificate, `InResponseTo` = `ArtifactResolve` ID | `InvalidSignature`, `InvalidResponse` |
| inner `Response` signed (configurable), status `Success` | `InvalidSignature`, `AuthenticationRejected` |
| one encrypted assertion; signature verified when present | `InvalidResponse`, `DecryptionFailed` |
| `InResponseTo` refers to a pending request of this browser session, used once | `ReplayDetected` |
| assertion ID never seen before (cache until expiry) | `ReplayDetected` |
| bearer `SubjectConfirmationData`: `Recipient`, `NotOnOrAfter`, `NotBefore` | `InvalidResponse` |
| `Conditions`: `NotBefore`, `NotOnOrAfter`, `Audience` = Issuer | `InvalidResponse` |
| `Destination`, `IssueInstant` window, `Version`; assertion `Issuer` required, IdP Issuer enforced when configured | `InvalidResponse` |
| level of assurance at least the requested one, four mandatory attributes present with exactly one value each | `InvalidResponse` |

Signature verification accepts only an enveloped signature that references the element it sits in (`URI=""` or
`URI="#ID"`), exclusive or inclusive canonicalization and SHA-256/384/512; SHA-1 is refused. Data is read only from
verified elements, which prevents signature wrapping. Documents with a DOCTYPE are refused.

`authnRequest()` and `redirect()` remember the request ID in the session of the given (or current) request, and
`resolveArtifact()` requires the answered request to come from that session while `security.bind_to_session` is
enabled (the default). Applications that resolve artifacts without a session must disable that setting explicitly and
bind the response to the user in another way.

The verified identity is kept in the session and is not tied to the authenticated guard user. When the application
switches the logged-in account in another way (impersonation, a second login form), call `session()->invalidate()`
first, so that the `wezel-krajowy.loa` middleware never trusts an identity from a previous account.

## Errors

| Exception | `reason()` | When |
| --- | --- | --- |
| `InvalidConfiguration` | `configuration` | missing Issuer, key, certificate or invalid setting |
| `ApiException` | `unavailable` | back channel unreachable, HTTP error, SOAP fault (`httpStatus`, `faultString`) |
| `AuthenticationRejected` | `authn_failed`, `request_denied`, `rejected` | non-success SAML status; `errorCode()` and `errorDescription()` explain the documented codes 1000 to 3004 |
| `InvalidSignature` | `invalid_signature` | missing, malformed or untrusted signature |
| `InvalidResponse` | `invalid_response` | protocol check failed |
| `ReplayDetected` | `replay` | reused assertion, unknown or foreign request |
| `DecryptionFailed` | `decryption` | wrong key or modified cipher text |
| `UserNotResolved` | `user_not_found` | the resolver returned no user |

All extend `WezelKrajowyException`. The routes catch them, report them, dispatch `AuthenticationFailed` and redirect to
`auth.failure_redirect` with the reason flashed as `wezel_krajowy_error`.

## Events

| Event | Payload |
| --- | --- |
| `UserAuthenticated` | `Identity $identity`, `?Authenticatable $user` |
| `AuthenticationFailed` | `WezelKrajowyException $exception`, `?Identity $identity` (set for `UserNotResolved`) |
| `UserLoggedOut` | `?Identity $identity`, `?LogoutResult $result`, `?WezelKrajowyException $exception` |

## Notes

- The login page posts the `AuthnRequest` with an inline `onload` script; with a strict Content Security Policy the
  user presses the "Kontynuuj" button instead.
- `ForceAuthn="true"` is always sent (the only value login.gov.pl accepts). Cross-border eIDAS login
  (`WEZEL_KRAJOWY_FOREIGN_AUTHENTICATION=true`) must be agreed with the ministry first.
- Artifact resolution and logout are never retried automatically; an artifact can be resolved only once.
- Not covered by the official guide and therefore not enforced: the exact Issuer value of login.gov.pl responses in
  each environment (set `WEZEL_KRAJOWY_IDP_ENTITY_ID` to enforce it) and RSA-OAEP encryption for RSA certificates
  (supported, but the guide documents ECDH-ES only).

## Development

```bash
composer install
composer ci   # pint --test, phpstan (level 8), pest
```

Tests generate throwaway EC and RSA keys and certificates at runtime and play the role of login.gov.pl: they sign and
encrypt responses exactly like the integration guide describes. `tests/Fixtures` holds the public metadata captured
from `int.login.gov.pl`. No request leaves the test suite and no private key is stored in the repository.

## Author

Created and maintained by **Kamil Ćwiertnia**, [beziworld.eu](https://beziworld.eu).

- E-mail: [biuro@beziworld.eu](mailto:biuro@beziworld.eu)
- Issues: [GitHub issues](https://github.com/beziworld/laravel-wezel-krajowy/issues)

Need an integration? Get in touch through [beziworld.eu](https://beziworld.eu).

### Other packages by the author

[laravel-edoreczenia](https://github.com/beziworld/laravel-edoreczenia) ·
[laravel-ksef](https://github.com/beziworld/laravel-ksef) ·
[laravel-polish-validation](https://github.com/beziworld/laravel-polish-validation) ·
[laravel-krs](https://github.com/beziworld/laravel-krs)

## License

MIT. See [LICENSE.md](LICENSE.md). login.gov.pl, Węzeł Krajowy, Profil Zaufany and mObywatel are services of the Polish
Ministry of Digital Affairs (Ministerstwo Cyfryzacji) operated by Centralny Ośrodek Informatyki. This package is not
affiliated with or endorsed by the Ministry of Digital Affairs or COI.
