# Laravel Węzeł Krajowy (login.gov.pl)

[![tests](https://github.com/beziworld/laravel-wezel-krajowy/actions/workflows/tests.yml/badge.svg)](https://github.com/beziworld/laravel-wezel-krajowy/actions/workflows/tests.yml)
[![Latest Version](https://img.shields.io/packagist/v/beziworld/laravel-wezel-krajowy.svg)](https://packagist.org/packages/beziworld/laravel-wezel-krajowy)
[![License](https://img.shields.io/packagist/l/beziworld/laravel-wezel-krajowy.svg)](LICENSE.md)

Logowanie do aplikacji Laravel przez **Węzeł Krajowy Identyfikacji Elektronicznej** ([login.gov.pl](https://login.gov.pl)):
Profil Zaufany, mObywatel, e-dowód i bankowość elektroniczna w ramach jednej integracji.

- dostawca usług SAML 2.0 w profilu login.gov.pl: podpisany `AuthnRequest` przez HTTP-POST, odpowiedź w wiązaniu
  **HTTP-Artifact**, `ArtifactResolve` kanałem zwrotnym SOAP, podpisane wylogowanie SOAP (`LogoutRequest`)
- podpisy XML ECDSA P-256 (oraz RSA-SHA256), odszyfrowanie asercji **ECDH-ES + ConcatKDF + AES-256 Key Wrap + AES-GCM**
  dokładnie tak, jak robi to login.gov.pl, transport klucza RSA-OAEP dla certyfikatów RSA
- ścisła walidacja: podpisy każdej warstwy względem przypiętych certyfikatów, `InResponseTo`, jednorazowe żądania, pamięć
  użytych asercji, `NotBefore` / `NotOnOrAfter` z tolerancją zegara, odbiorca (audience), `Recipient`, `Destination`,
  poziom bezpieczeństwa eIDAS, obowiązkowe atrybuty
- gotowe trasy (logowanie, odbiór artefaktu, wylogowanie, metadane dostawcy usług), zdarzenie `UserAuthenticated`
  z typowanym obiektem `Identity` (imię, nazwisko, data urodzenia, PESEL, poziom bezpieczeństwa, dostawca tożsamości),
  resolver użytkownika, który loguje go w aplikacji, middleware `wezel-krajowy.loa:high`
- środowisko integracyjne (`int.login.gov.pl`), produkcja dla podmiotów publicznych (`login.gov.pl`) i dla podmiotów
  prywatnych (`podmiotyzewnetrzne.login.gov.pl`), z możliwością nadpisania adresów (np. symulator)
- polecenia Artisan `wezel-krajowy:metadata` i `wezel-krajowy:idp-metadata`

[English documentation](README.md)

## Dlaczego ten pakiet

W chwili pisania Packagist nie zawiera żadnego pakietu dla login.gov.pl, Profilu Zaufanego ani Węzła Krajowego
(wyszukiwania "profil zaufany", "wezel krajowy", "login-gov-pl" nie zwracają wyników; "epuap" zwraca dwie stare
biblioteki ePUAP sprzed uruchomienia węzła). Ogólne biblioteki SAML dla PHP nie pasują do tego profilu:
`onelogin/php-saml` nie obsługuje wiązania HTTP-Artifact ani ECDSA, a `robrichards/xmlseclibs` podpisuje wyłącznie RSA/HMAC
i nie ma ECDH-ES, ConcatKDF ani AES Key Wrap. Dlatego pakiet implementuje wąski podzbiór XML Signature / XML Encryption,
którego używa login.gov.pl, w oparciu o kanonikalizację `ext-dom`, [phpseclib 3](https://phpseclib.com) (ECDSA, ECDH,
RSA, X.509) i `ext-openssl` (AES-GCM, AES dla RFC 3394). Weryfikator sprawdzono na prawdziwych podpisach ECDSA
w publicznych metadanych wszystkich trzech środowisk login.gov.pl.

## Zanim zaczniesz

Dostęp przyznaje Ministerstwo Cyfryzacji, nie ma samoobsługowej rejestracji:

1. Złóż pismo o dostęp do środowiska integracyjnego na portalu [Współpraca Cyfrowa Tożsamość](https://wspolpraca.ct.gov.pl).
   COI przekaże certyfikaty testowe, wartość Issuer, hasła i scenariusze testowe.
2. Zgłoś swój SAML Issuer, adres odbioru asercji (`https://twoja-aplikacja/wezel-krajowy/acs`) oraz adresy IP, z których
   łączy się aplikacja. Dostęp aktywuje pierwszy poprawnie podpisany `AuthnRequest`.
3. Po testach złóż wniosek o przyłączenie produkcyjne. Produkcja wymaga dwóch certyfikatów od kwalifikowanego dostawcy
   usług zaufania: do podpisu (ECDSA P-256 lub RSA-SHA256, rozszerzenie Digital Signature) i do deszyfracji
   (rozszerzenie Key Agreement). login.gov.pl wymaga osobnych kluczy do podpisu i do deszyfracji.

## Instalacja

```bash
composer require beziworld/laravel-wezel-krajowy
php artisan vendor:publish --tag=wezel-krajowy-config   # opcjonalnie
```

```dotenv
WEZEL_KRAJOWY_ENV=integration                 # integration | production | production-private
WEZEL_KRAJOWY_ISSUER=https://twoja-aplikacja.pl   # SAML Issuer zgłoszony do COI
WEZEL_KRAJOWY_PROVIDER_NAME=twoja-aplikacja   # ProviderName uzgodniony z COI
WEZEL_KRAJOWY_SP_TYPE=public                  # public | private (eIDAS SPType)

WEZEL_KRAJOWY_SIGNING_KEY=/secure/wk-sign.key        # ścieżka lub PEM (EC P-256 albo RSA)
WEZEL_KRAJOWY_SIGNING_CERTIFICATE=/secure/wk-sign.crt
WEZEL_KRAJOWY_SIGNING_PASSPHRASE=
WEZEL_KRAJOWY_ENCRYPTION_KEY=/secure/wk-enc.key
WEZEL_KRAJOWY_ENCRYPTION_CERTIFICATE=/secure/wk-enc.crt
WEZEL_KRAJOWY_ENCRYPTION_PASSPHRASE=

# Przypięte certyfikaty podpisu login.gov.pl (zalecane) ...
WEZEL_KRAJOWY_IDP_CERTIFICATES=/secure/login-gov-pl-ec.pem,/secure/login-gov-pl-rsa.pem
# ... albo odczyt z publicznych metadanych środowiska przez HTTPS:
WEZEL_KRAJOWY_TRUST_METADATA=false

WEZEL_KRAJOWY_LOA=substantial                 # low | substantial | high
WEZEL_KRAJOWY_CACHE_STORE=                    # wspólny magazyn cache dla oczekujących żądań
```

Pobranie aktualnych certyfikatów login.gov.pl do przypięcia:

```bash
php artisan wezel-krajowy:idp-metadata --save=storage/app/wezel-krajowy
```

Klucze prywatne trzymaj poza repozytorium i poza katalogiem publicznym, z prawem odczytu wyłącznie dla użytkownika
PHP (na przykład `chmod 600`, właściciel to konto serwera WWW), i wskazuj je jako pliki zamiast wklejać PEM do `.env`.
Sesja przechowuje zweryfikowaną tożsamość razem z numerem PESEL, dlatego włącz `SESSION_ENCRYPT=true` i używaj
sterownika sesji po stronie serwera. Gdy znasz wartość Issuer, której login.gov.pl używa w Twoim środowisku, ustaw
`WEZEL_KRAJOWY_IDP_ENTITY_ID`, aby ją wymuszać. Rozważ dodanie `throttle` do `routes.middleware`, ponieważ każde wejście
na trasę logowania zapisuje oczekujące żądanie w cache.

## Logowanie

Pakiet rejestruje trasy (prefiks i middleware można zmienić w konfiguracji):

| Metoda | URI | Nazwa | Działanie |
| --- | --- | --- | --- |
| GET | `/wezel-krajowy/login?return_to=/orders&loa=high` | `wezel-krajowy.login` | podpisuje `AuthnRequest` i automatycznie wysyła go do login.gov.pl |
| POST | `/wezel-krajowy/acs` | `wezel-krajowy.acs.post` | odbiera `SAMLart` z przeglądarki i przekierowuje (303) na wariant GET |
| GET | `/wezel-krajowy/acs` | `wezel-krajowy.acs` | rozwiązuje artefakt, waliduje asercję, loguje użytkownika |
| POST | `/wezel-krajowy/logout` | `wezel-krajowy.logout` | wylogowanie w login.gov.pl, potem lokalne |
| GET | `/wezel-krajowy/metadata` | `wezel-krajowy.metadata` | metadane dostawcy usług |

Przeglądarka wraca z login.gov.pl żądaniem POST z innej domeny, które nie niesie ciasteczka sesji `SameSite=Lax` ani
tokenu CSRF. Trasa POST nie ma middleware i odpowiada tylko przekierowaniem 303 na trasę GET, gdzie sesja jest już
dostępna. Oczekujące żądania są przechowywane w cache, więc przetrwają ten krok.

```blade
<a href="{{ route('wezel-krajowy.login', ['return_to' => '/orders']) }}">Zaloguj przez login.gov.pl</a>

<form method="post" action="{{ route('wezel-krajowy.logout') }}">@csrf <button>Wyloguj</button></form>

@if (session('wezel_krajowy_error'))
    <p>Logowanie nie powiodło się ({{ session('wezel_krajowy_error') }}).</p>
@endif
```

Przypisz tożsamość do użytkownika. Pakiet loguje zwróconego użytkownika przez skonfigurowany guard i regeneruje sesję;
zwrócenie `null` odrzuca logowanie:

```php
use Beziworld\WezelKrajowy\Data\Identity;
use Beziworld\WezelKrajowy\Facades\WezelKrajowy;

// AppServiceProvider::boot()
WezelKrajowy::resolveUsersUsing(function (Identity $identity) {
    return User::where('pesel', $identity->pesel)->first();
});
```

Można też zaimplementować `Beziworld\WezelKrajowy\Contracts\IdentityResolver` i wskazać klasę w `auth.resolver`. Bez
resolvera tożsamość trafia do sesji i do zdarzenia, a logowanie obsługuje aplikacja.

## Tożsamość

```php
use Beziworld\WezelKrajowy\Events\UserAuthenticated;

Event::listen(function (UserAuthenticated $event) {
    $identity = $event->identity;

    $identity->firstName;          // "Jan"
    $identity->familyName;         // "Niezbędny"
    $identity->dateOfBirth;        // CarbonImmutable 1986-07-25, Europe/Warsaw
    $identity->pesel;              // "86072500004" (null dla zagranicznych tożsamości eIDAS)
    $identity->personIdentifier;   // surowy eIDAS PersonIdentifier
    $identity->levelOfAssurance;   // LevelOfAssurance::Substantial
    $identity->identityProvider;   // "pz.gov.pl" (AuthenticatingAuthority)
    $identity->nameId;             // NameID używany przy wylogowaniu
    $identity->sessionIndex;
    $identity->attribute('BirthName');   // atrybuty opcjonalne, jeśli zostały zażądane
    $event->user;                  // zalogowany użytkownik albo null bez resolvera
});

WezelKrajowy::identity();          // tożsamość bieżącej sesji
```

Atrybuty opcjonalne (BirthName, PlaceOfBirth, CurrentAddress, Gender i pozostałe z metadanych) włącza się w
`authn.attributes`; nie ma gwarancji, że dostawca tożsamości je przekaże.

## Poziom bezpieczeństwa

`WEZEL_KRAJOWY_LOA` to minimum dla każdego logowania. Trasa może wymagać więcej:

```php
Route::middleware('wezel-krajowy.loa:high')->get('/podpis', SignController::class);
```

Użytkownik z niższym poziomem jest kierowany do ponownego logowania z `loa=high`; żądania JSON dostają 401. Odpowiedź,
w której `AuthnContextClassRef` jest niższy niż żądany, jest odrzucana.

## Bezpośrednie użycie serwisu

```php
$response = WezelKrajowy::redirect('/orders', LevelOfAssurance::High);  // formularz HTML z automatycznym wysłaniem
$message  = WezelKrajowy::authnRequest('/orders');                      // podpisany XML + pola formularza
$result   = WezelKrajowy::resolveArtifact($request->query('SAMLart'), $request);  // AuthenticationResult
$logout   = WezelKrajowy::logoutIdentity($identity);                    // LogoutResult: successful(), partial()
$xml      = WezelKrajowy::serviceProviderMetadata();
$idp      = WezelKrajowy::identityProviderMetadata();                   // adresy usług, certyfikaty
```

## Kontrole bezpieczeństwa

| Kontrola | Błąd |
| --- | --- |
| `ArtifactResponse` podpisany zaufanym certyfikatem login.gov.pl, `InResponseTo` = ID `ArtifactResolve` | `InvalidSignature`, `InvalidResponse` |
| wewnętrzny `Response` podpisany (konfigurowalne), status `Success` | `InvalidSignature`, `AuthenticationRejected` |
| dokładnie jedna zaszyfrowana asercja; podpis asercji weryfikowany, jeśli jest | `InvalidResponse`, `DecryptionFailed` |
| `InResponseTo` wskazuje oczekujące żądanie tej sesji przeglądarki, użyte jeden raz | `ReplayDetected` |
| ID asercji nie był wcześniej użyty (pamiętany w cache do wygaśnięcia) | `ReplayDetected` |
| `SubjectConfirmationData` typu bearer: `Recipient`, `NotOnOrAfter`, `NotBefore` | `InvalidResponse` |
| `Conditions`: `NotBefore`, `NotOnOrAfter`, `Audience` = Issuer | `InvalidResponse` |
| `Destination`, okno `IssueInstant`, `Version`; wymagany `Issuer` asercji, Issuer login.gov.pl wymuszany po skonfigurowaniu | `InvalidResponse` |
| poziom bezpieczeństwa co najmniej żądany, cztery obowiązkowe atrybuty, każdy z dokładnie jedną wartością | `InvalidResponse` |

Weryfikacja przyjmuje wyłącznie podpis typu enveloped, który wskazuje element, w którym się znajduje (`URI=""` lub
`URI="#ID"`), kanonikalizację wyłączną lub włączną oraz SHA-256/384/512; SHA-1 jest odrzucane. Dane są odczytywane
tylko ze zweryfikowanych elementów, co zapobiega atakom typu signature wrapping. Dokumenty z DOCTYPE są odrzucane.

`authnRequest()` i `redirect()` zapamiętują ID żądania w sesji przekazanego (lub bieżącego) żądania HTTP, a
`resolveArtifact()` wymaga, aby obsługiwane żądanie pochodziło z tej sesji, dopóki `security.bind_to_session` jest
włączone (domyślnie). Aplikacje rozwiązujące artefakty bez sesji muszą jawnie wyłączyć to ustawienie i powiązać
odpowiedź z użytkownikiem w inny sposób.

Zweryfikowana tożsamość jest przechowywana w sesji i nie jest powiązana z użytkownikiem zalogowanym w guardzie. Gdy
aplikacja przełącza konto w inny sposób (impersonacja, drugi formularz logowania), najpierw wywołaj
`session()->invalidate()`, aby middleware `wezel-krajowy.loa` nie zaufało tożsamości z poprzedniego konta.

## Błędy

| Wyjątek | `reason()` | Kiedy |
| --- | --- | --- |
| `InvalidConfiguration` | `configuration` | brak Issuer, klucza, certyfikatu lub błędne ustawienie |
| `ApiException` | `unavailable` | kanał zwrotny niedostępny, błąd HTTP, SOAP Fault (`httpStatus`, `faultString`) |
| `AuthenticationRejected` | `authn_failed`, `request_denied`, `rejected` | status SAML inny niż sukces; `errorCode()` i `errorDescription()` objaśniają udokumentowane kody od 1000 do 3004 |
| `InvalidSignature` | `invalid_signature` | brak podpisu, podpis błędny lub niezaufany |
| `InvalidResponse` | `invalid_response` | nieudana kontrola protokołu |
| `ReplayDetected` | `replay` | ponowne użycie asercji, nieznane lub obce żądanie |
| `DecryptionFailed` | `decryption` | zły klucz lub zmodyfikowany szyfrogram |
| `UserNotResolved` | `user_not_found` | resolver nie zwrócił użytkownika |

Wszystkie dziedziczą po `WezelKrajowyException`. Trasy przechwytują je, raportują, wysyłają zdarzenie
`AuthenticationFailed` i przekierowują na `auth.failure_redirect`, zapisując przyczynę w sesji jako `wezel_krajowy_error`.

## Zdarzenia

| Zdarzenie | Dane |
| --- | --- |
| `UserAuthenticated` | `Identity $identity`, `?Authenticatable $user` |
| `AuthenticationFailed` | `WezelKrajowyException $exception`, `?Identity $identity` (ustawione dla `UserNotResolved`) |
| `UserLoggedOut` | `?Identity $identity`, `?LogoutResult $result`, `?WezelKrajowyException $exception` |

## Uwagi

- Strona logowania wysyła `AuthnRequest` skryptem w atrybucie `onload`; przy restrykcyjnej polityce Content Security
  Policy użytkownik klika przycisk "Kontynuuj".
- Zawsze wysyłane jest `ForceAuthn="true"` (jedyna wartość akceptowana przez login.gov.pl). Logowanie transgraniczne
  eIDAS (`WEZEL_KRAJOWY_FOREIGN_AUTHENTICATION=true`) wymaga wcześniejszego uzgodnienia z ministerstwem.
- Rozwiązanie artefaktu i wylogowanie nigdy nie są automatycznie ponawiane; artefakt można rozwiązać tylko raz.
- Poza oficjalną instrukcją, więc nie jest wymuszane: dokładna wartość Issuer w odpowiedziach login.gov.pl w każdym
  środowisku (ustaw `WEZEL_KRAJOWY_IDP_ENTITY_ID`, aby ją wymusić) oraz szyfrowanie RSA-OAEP dla certyfikatów RSA
  (obsługiwane, ale instrukcja opisuje tylko ECDH-ES).

## Rozwój

```bash
composer install
composer ci   # pint --test, phpstan (poziom 8), pest
```

Testy generują jednorazowe klucze i certyfikaty EC oraz RSA w czasie uruchomienia i odgrywają rolę login.gov.pl:
podpisują i szyfrują odpowiedzi dokładnie tak, jak opisuje instrukcja integratora. `tests/Fixtures` zawiera publiczne
metadane pobrane z `int.login.gov.pl`. Żadne żądanie nie opuszcza testów, a w repozytorium nie ma kluczy prywatnych.

## Autor

Pakiet tworzy i utrzymuje **Kamil Ćwiertnia**, [beziworld.eu](https://beziworld.eu).

- E-mail: [biuro@beziworld.eu](mailto:biuro@beziworld.eu)
- Zgłoszenia: [GitHub issues](https://github.com/beziworld/laravel-wezel-krajowy/issues)

Potrzebujesz integracji? Skontaktuj się przez [beziworld.eu](https://beziworld.eu).

### Inne pakiety autora

[laravel-edoreczenia](https://github.com/beziworld/laravel-edoreczenia) ·
[laravel-ksef](https://github.com/beziworld/laravel-ksef) ·
[laravel-polish-validation](https://github.com/beziworld/laravel-polish-validation) ·
[laravel-krs](https://github.com/beziworld/laravel-krs)

## Licencja

MIT. Zobacz [LICENSE.md](LICENSE.md). login.gov.pl, Węzeł Krajowy, Profil Zaufany i mObywatel są usługami Ministerstwa
Cyfryzacji obsługiwanymi przez Centralny Ośrodek Informatyki. Pakiet nie jest powiązany z Ministerstwem Cyfryzacji ani
z COI i nie jest przez nie wspierany.
