<?php

namespace Oleant\VisitAnalytics;

use Illuminate\Support\ServiceProvider;

class VisitAnalyticsServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Merge package configuration with the application's copy
        $this->mergeConfigFrom(
            __DIR__.'/../config/visit-analytics.php', 'visit-analytics'
        );
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Load package migrations automatically
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        if ($this->app->runningInConsole()) {
            
            // Registering the bot analysis command
            $this->commands([
                \Oleant\VisitAnalytics\Console\Commands\AnalyzeBots::class,
            ]);

            // Publishing the configuration file
            $this->publishes([
                __DIR__.'/../config/visit-analytics.php' => config_path('visit-analytics.php'),
            ], 'visit-analytics-config');

            // Publishing migrations for manual customization
            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'visit-analytics-migrations');
        }
    }
}