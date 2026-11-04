<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Beziworld\WezelKrajowy\WezelKrajowyConfig config()
 * @method static string acsUrl()
 * @method static \Beziworld\WezelKrajowy\Data\AuthnRequestMessage authnRequest(?string $returnTo = null, ?\Beziworld\WezelKrajowy\Enums\LevelOfAssurance $levelOfAssurance = null, ?\Illuminate\Http\Request $request = null)
 * @method static \Illuminate\Http\Response redirect(?string $returnTo = null, ?\Beziworld\WezelKrajowy\Enums\LevelOfAssurance $levelOfAssurance = null, ?\Illuminate\Http\Request $request = null)
 * @method static \Beziworld\WezelKrajowy\Data\AuthenticationResult resolveArtifact(string $artifact, ?\Illuminate\Http\Request $request = null)
 * @method static \Beziworld\WezelKrajowy\Data\LogoutResult logout(string $nameId, ?string $sessionIndex, ?string $nameIdFormat = null)
 * @method static \Beziworld\WezelKrajowy\Data\LogoutResult logoutIdentity(\Beziworld\WezelKrajowy\Data\Identity $identity)
 * @method static string serviceProviderMetadata()
 * @method static \Beziworld\WezelKrajowy\Data\IdpMetadata identityProviderMetadata(bool $fresh = false)
 * @method static \Beziworld\WezelKrajowy\WezelKrajowy resolveUsersUsing((\Closure(\Beziworld\WezelKrajowy\Data\Identity): (\Illuminate\Contracts\Auth\Authenticatable|null))|\Beziworld\WezelKrajowy\Contracts\IdentityResolver|null $resolver)
 * @method static bool hasUserResolver()
 * @method static \Illuminate\Contracts\Auth\Authenticatable|null resolveUser(\Beziworld\WezelKrajowy\Data\Identity $identity)
 * @method static \Beziworld\WezelKrajowy\Data\Identity|null identity(?\Illuminate\Http\Request $request = null)
 * @method static \Beziworld\WezelKrajowy\Security\KeyPair signingKey()
 * @method static \Beziworld\WezelKrajowy\Security\KeyPair encryptionKey()
 * @method static \Beziworld\WezelKrajowy\Saml\IdentityProviderCertificates certificates()
 *
 * @see \Beziworld\WezelKrajowy\WezelKrajowy
 */
final class WezelKrajowy extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Beziworld\WezelKrajowy\WezelKrajowy::class;
    }
}
