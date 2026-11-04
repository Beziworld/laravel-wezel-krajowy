<?php

declare(strict_types=1);

namespace Beziworld\WezelKrajowy;

use Beziworld\WezelKrajowy\Console\IdpMetadataCommand;
use Beziworld\WezelKrajowy\Console\MetadataCommand;
use Beziworld\WezelKrajowy\Http\Middleware\RequireLevelOfAssurance;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\ServiceProvider;

/**
 * Registers the login.gov.pl service, routes, middleware alias and commands.
 */
final class WezelKrajowyServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/wezel-krajowy.php', 'wezel-krajowy');

        $this->app->singleton(WezelKrajowyConfig::class, static function (Container $app): WezelKrajowyConfig {
            $config = $app->make('config');
            $values = $config->get('wezel-krajowy', []);

            return WezelKrajowyConfig::fromArray(is_array($values) ? $values : []);
        });

        $this->app->singleton(WezelKrajowy::class, static function (Container $app): WezelKrajowy {
            $config = $app->make('config');
            $resolver = $config->get('wezel-krajowy.auth.resolver');

            return new WezelKrajowy(
                $app->make(WezelKrajowyConfig::class),
                $app->make(HttpFactory::class),
                $app->make(CacheFactory::class),
                $app->make(UrlGenerator::class),
                $app,
                is_string($resolver) && $resolver !== '' ? $resolver : null,
            );
        });

        $this->app->alias(WezelKrajowy::class, 'wezel-krajowy');
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/wezel-krajowy.php' => $this->app->configPath('wezel-krajowy.php'),
        ], 'wezel-krajowy-config');

        $config = $this->app->make('config');

        if ((bool) $config->get('wezel-krajowy.routes.enabled', true)) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/wezel-krajowy.php');
        }

        $this->app->make('router')->aliasMiddleware('wezel-krajowy.loa', RequireLevelOfAssurance::class);

        if ($this->app->runningInConsole()) {
            $this->commands([MetadataCommand::class, IdpMetadataCommand::class]);
        }
    }
}
