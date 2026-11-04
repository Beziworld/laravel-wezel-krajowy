<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Enums;

/**
 * Natural person attributes published in the login.gov.pl metadata.
 *
 * The case names are the FriendlyName values, the case values are the
 * attribute Name URIs.
 */
enum EidasAttribute: string
{
    case FirstName = 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName';
    case FamilyName = 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName';
    case DateOfBirth = 'http://eidas.europa.eu/attributes/naturalperson/DateOfBirth';
    case PersonIdentifier = 'http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier';
    case BirthName = 'http://eidas.europa.eu/attributes/naturalperson/BirthName';
    case PlaceOfBirth = 'http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth';
    case CurrentAddress = 'http://eidas.europa.eu/attributes/naturalperson/CurrentAddress';
    case Gender = 'http://eidas.europa.eu/attributes/naturalperson/Gender';
    case CountryOfBirth = 'http://eidas.europa.eu/attributes/naturalperson/CountryOfBirth';
    case CountryOfResidence = 'http://eidas.europa.eu/attributes/naturalperson/CountryOfResidence';
    case Nationality = 'http://eidas.europa.eu/attributes/naturalperson/Nationality';
    case TownOfBirth = 'http://eidas.europa.eu/attributes/naturalperson/TownOfBirth';
    case EmailAddress = 'http://eidas.europa.eu/attributes/naturalperson/EmailAddress';
    case PhoneNumber = 'http://eidas.europa.eu/attributes/naturalperson/PhoneNumber';

    /**
     * The minimum data set that every AuthnRequest must request as required.
     *
     * @return list<self>
     */
    public static function mandatory(): array
    {
        return [self::FamilyName, self::FirstName, self::DateOfBirth, self::PersonIdentifier];
    }

    public static function fromFriendlyName(string $name): ?self
    {
        foreach (self::cases() as $case) {
            if (strcasecmp($case->name, trim($name)) === 0 || $case->value === trim($name)) {
                return $case;
            }
        }

        return null;
    }

    public function isMandatory(): bool
    {
        return in_array($this, self::mandatory(), true);
    }
}
