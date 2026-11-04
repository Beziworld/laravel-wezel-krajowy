<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy\Console;

use Beziworld\WezelKrajowy\Exceptions\WezelKrajowyException;
use Beziworld\WezelKrajowy\WezelKrajowy;
use Illuminate\Console\Command;

/**
 * Prints (or writes to a file) the service provider metadata.
 */
final class MetadataCommand extends Command
{
    /** @var string */
    protected $signature = 'wezel-krajowy:metadata {--output= : Write the metadata to this file instead of printing it}';

    /** @var string */
    protected $description = 'Generate the login.gov.pl service provider metadata (issuer, certificates, assertion consumer URL)';

    public function handle(WezelKrajowy $wezelKrajowy): int
    {
        try {
            $xml = $wezelKrajowy->serviceProviderMetadata();
        } catch (WezelKrajowyException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $output = $this->option('output');

        if (is_string($output) && $output !== '') {
            if (file_put_contents($output, $xml) === false) {
                $this->error(sprintf('Could not write %s.', $output));

                return self::FAILURE;
            }

            $this->info(sprintf('Metadata written to %s.', $output));

            return self::SUCCESS;
        }

        $this->line($xml);

        return self::SUCCESS;
    }
}
