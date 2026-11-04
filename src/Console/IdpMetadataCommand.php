<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Console;

use Beziworld\WezelKrajowy\Exceptions\WezelKrajowyException;
use Beziworld\WezelKrajowy\Security\Certificate;
use Beziworld\WezelKrajowy\WezelKrajowy;
use Illuminate\Console\Command;

/**
 * Downloads the public login.gov.pl metadata, shows endpoints and signing
 * certificates, and optionally saves the certificates as PEM files for pinning.
 */
final class IdpMetadataCommand extends Command
{
    /** @var string */
    protected $signature = 'wezel-krajowy:idp-metadata {--save= : Directory to store the signing certificates as PEM files}';

    /** @var string */
    protected $description = 'Show the login.gov.pl metadata (endpoints, signing certificates) of the configured environment';

    public function handle(WezelKrajowy $wezelKrajowy): int
    {
        try {
            $metadata = $wezelKrajowy->identityProviderMetadata(true);
            $certificates = array_map(static fn(string $der): Certificate => Certificate::load($der, 'idp metadata'), $metadata->signingCertificates);
        } catch (WezelKrajowyException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->components->twoColumnDetail('Entity ID', $metadata->entityId);
        $this->components->twoColumnDetail('Valid until', $metadata->validUntil?->toIso8601ZuluString() ?? '-');
        $this->components->twoColumnDetail('SingleSignOnService', $metadata->ssoUrl ?? '-');
        $this->components->twoColumnDetail('ArtifactResolutionService', $metadata->artifactResolutionUrl ?? '-');
        $this->components->twoColumnDetail('SingleLogoutService', $metadata->singleLogoutUrl ?? '-');
        $this->components->twoColumnDetail('Signing methods', implode(', ', $metadata->signingMethods));

        $rows = [];

        foreach ($certificates as $index => $certificate) {
            $rows[] = [
                $index + 1,
                $certificate->subject(),
                $certificate->isEc() ? 'EC' : 'RSA',
                $certificate->validTo()?->toDateString() ?? '-',
                $certificate->fingerprint(),
            ];
        }

        $this->table(['#', 'Subject', 'Key', 'Valid to', 'SHA-256 fingerprint'], $rows);

        $directory = $this->option('save');

        if (is_string($directory) && $directory !== '') {
            if (! is_dir($directory) && ! mkdir($directory, 0755, true) && ! is_dir($directory)) {
                $this->error(sprintf('Could not create %s.', $directory));

                return self::FAILURE;
            }

            $paths = [];

            foreach ($certificates as $certificate) {
                $path = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . 'login-gov-pl-' . substr($certificate->fingerprint(), 0, 16) . '.pem';
                file_put_contents($path, $certificate->pem());
                $paths[] = $path;
            }

            $this->info('Saved. Pin them with WEZEL_KRAJOWY_IDP_CERTIFICATES=' . implode(',', $paths));
        }

        return self::SUCCESS;
    }
}
