# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- SAML 2.0 service provider for login.gov.pl (Węzeł Krajowy): signed AuthnRequest over HTTP-POST with the eIDAS
  extensions (SPType, RequestedAttributes), HTTP-Artifact response binding and ArtifactResolve over SOAP.
- ECDSA P-256 and RSA-SHA256 XML signatures in the documented login.gov.pl layout; strict enveloped signature
  verification resistant to signature wrapping.
- Assertion decryption with ECDH-ES, ConcatKDF, AES key wrap and AES-GCM (including 128-bit content keys), plus
  RSA-OAEP key transport.
- Response validation: InResponseTo, one-time pending requests bound to the browser session, assertion replay cache,
  validity window with clock skew, audience, recipient, destination, level of assurance, mandatory attributes.
- `Identity` data object with PESEL extraction, `UserAuthenticated`, `AuthenticationFailed` and `UserLoggedOut` events,
  user resolver hook with guard login, `wezel-krajowy.loa` middleware.
- Routes for login, assertion consumer (POST to GET bounce for SameSite cookies), single logout over SOAP and service
  provider metadata.
- Environments: integration, production and production for private entities, with endpoint overrides.
- Pinned login.gov.pl certificates or certificates read from the public metadata; `wezel-krajowy:metadata` and
  `wezel-krajowy:idp-metadata` commands.

### Security

- `resolveArtifact()` enforces the session binding itself (previously only the bundled route did), and
  `authnRequest()` remembers the request ID in the session, so custom login flows are protected against login CSRF.
- The assertion must carry an Issuer, and the bearer `SubjectConfirmationData` must carry `InResponseTo`.
- An `ArtifactResponse` with more than one `Response` is rejected.
- An attribute with an unknown Name can no longer supply a well-known attribute through its FriendlyName, and the
  mandatory attributes must have exactly one value.
