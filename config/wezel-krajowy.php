<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Environment
    |--------------------------------------------------------------------------
    |
    | "integration" (int.login.gov.pl, COI test environment), "production"
    | (login.gov.pl, public entities) or "production-private"
    | (podmiotyzewnetrzne.login.gov.pl, private entities). Each endpoint can be
    | overridden below, for example to point at a simulator.
    |
    */

    'environment' => env('WEZEL_KRAJOWY_ENV', 'integration'),

    /*
    |--------------------------------------------------------------------------
    | Service provider (your application)
    |--------------------------------------------------------------------------
    |
    | "entity_id" is the SAML Issuer registered with COI. "provider_name" is the
    | ProviderName value agreed with COI during onboarding. Keys and
    | certificates accept a file path or an inline PEM string. The signing key
    | (ECDSA P-256 or RSA) signs AuthnRequest, ArtifactResolve and
    | LogoutRequest; the encryption key decrypts assertions. login.gov.pl
    | requires two separate key pairs.
    |
    */

    'sp' => [
        'entity_id' => env('WEZEL_KRAJOWY_ISSUER'),
        'provider_name' => env('WEZEL_KRAJOWY_PROVIDER_NAME'),
        'type' => env('WEZEL_KRAJOWY_SP_TYPE', 'public'),
        'acs_url' => env('WEZEL_KRAJOWY_ACS_URL'),
        'signing' => [
            'key' => env('WEZEL_KRAJOWY_SIGNING_KEY'),
            'certificate' => env('WEZEL_KRAJOWY_SIGNING_CERTIFICATE'),
            'passphrase' => env('WEZEL_KRAJOWY_SIGNING_PASSPHRASE'),
        ],
        'encryption' => [
            'key' => env('WEZEL_KRAJOWY_ENCRYPTION_KEY'),
            'certificate' => env('WEZEL_KRAJOWY_ENCRYPTION_CERTIFICATE'),
            'passphrase' => env('WEZEL_KRAJOWY_ENCRYPTION_PASSPHRASE'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Identity provider (login.gov.pl)
    |--------------------------------------------------------------------------
    |
    | "certificates" pins the signing certificates of login.gov.pl (comma
    | separated file paths or inline PEM). When empty and "trust_metadata" is
    | true, the signing certificates are read from the public metadata of the
    | selected environment over HTTPS and cached. "entity_id" is enforced as
    | the expected Issuer of responses only when set.
    |
    */

    'idp' => [
        'entity_id' => env('WEZEL_KRAJOWY_IDP_ENTITY_ID'),
        'certificates' => array_values(array_filter(array_map('trim', explode(',', (string) env('WEZEL_KRAJOWY_IDP_CERTIFICATES', ''))))),
        'trust_metadata' => (bool) env('WEZEL_KRAJOWY_TRUST_METADATA', false),
        'metadata_url' => env('WEZEL_KRAJOWY_METADATA_URL'),
        'metadata_cache_ttl' => (int) env('WEZEL_KRAJOWY_METADATA_CACHE_TTL', 3600),
        'sso_url' => env('WEZEL_KRAJOWY_SSO_URL'),
        'artifact_resolution_url' => env('WEZEL_KRAJOWY_ARTIFACT_RESOLUTION_URL'),
        'slo_url' => env('WEZEL_KRAJOWY_SLO_URL'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication request
    |--------------------------------------------------------------------------
    |
    | "level_of_assurance": low, substantial or high (eIDAS). "attributes":
    | optional eIDAS attributes requested in addition to the four mandatory
    | ones (FirstName, FamilyName, DateOfBirth, PersonIdentifier), for example
    | ["BirthName", "CurrentAddress"]. "foreign_authentication" enables
    | cross-border eIDAS login and must be agreed with the ministry first.
    |
    */

    'authn' => [
        'level_of_assurance' => env('WEZEL_KRAJOWY_LOA', 'substantial'),
        'name_id_format' => env('WEZEL_KRAJOWY_NAME_ID_FORMAT', 'unspecified'),
        'attributes' => [],
        'foreign_authentication' => (bool) env('WEZEL_KRAJOWY_FOREIGN_AUTHENTICATION', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Security
    |--------------------------------------------------------------------------
    |
    | "clock_skew" in seconds tolerated on NotBefore / NotOnOrAfter.
    | "request_ttl" is how long a pending AuthnRequest stays valid.
    | "cache_store" holds pending requests and consumed assertion IDs; use a
    | store shared by all application servers. "bind_to_session" requires the
    | response to arrive in the browser session that started the login.
    |
    */

    'security' => [
        'clock_skew' => (int) env('WEZEL_KRAJOWY_CLOCK_SKEW', 120),
        'request_ttl' => (int) env('WEZEL_KRAJOWY_REQUEST_TTL', 900),
        'require_signed_response' => true,
        'bind_to_session' => true,
        'cache_store' => env('WEZEL_KRAJOWY_CACHE_STORE'),
    ],

    'http' => [
        'timeout' => (int) env('WEZEL_KRAJOWY_TIMEOUT', 30),
        'connect_timeout' => (int) env('WEZEL_KRAJOWY_CONNECT_TIMEOUT', 10),
    ],

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | Registers GET {prefix}/login, POST|GET {prefix}/acs, POST {prefix}/logout
    | and GET {prefix}/metadata. The browser POST to the assertion consumer
    | is answered with a 303 redirect to the GET variant so that SameSite=Lax
    | session cookies are available when the login completes.
    |
    */

    'routes' => [
        'enabled' => true,
        'prefix' => 'wezel-krajowy',
        'middleware' => ['web'],
        'domain' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | Application login
    |--------------------------------------------------------------------------
    |
    | "resolver" is a class implementing
    | Beziworld\WezelKrajowy\Contracts\IdentityResolver; it maps the verified
    | identity to a local user. When it returns a user, the package logs it in
    | through "guard". Without a resolver the identity is only stored in the
    | session and announced with the UserAuthenticated event.
    |
    */

    'auth' => [
        'guard' => env('WEZEL_KRAJOWY_GUARD'),
        'resolver' => null,
        'remember' => false,
        'redirect' => '/',
        'failure_redirect' => '/login',
        'logout_redirect' => '/',
    ],

];
