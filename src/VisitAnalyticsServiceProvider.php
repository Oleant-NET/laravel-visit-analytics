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
        $configs = [
            'visit-analytics-collection'   => 'visit-analytics-collection.php',
            'visit-analytics-detection'    => 'visit-analytics-detection.php',
            'visit-analytics-retroactive'  => 'visit-analytics-retroactive.php',
        ];

        foreach ($configs as $key => $file) {
            $this->mergeConfigFrom(__DIR__.'/../config/'.$file, $key);
        }
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        if ($this->app->runningInConsole()) {
            
            $this->commands([
                \Oleant\VisitAnalytics\Console\Commands\AnalyzeBots::class,
            ]);

            $this->publishes([
                __DIR__.'/../config/visit-analytics-collection.php'   => config_path('visit-analytics-collection.php'),
                __DIR__.'/../config/visit-analytics-detection.php'    => config_path('visit-analytics-detection.php'),
                __DIR__.'/../config/visit-analytics-retroactive.php'  => config_path('visit-analytics-retroactive.php'),
            ], 'visit-analytics-config');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'visit-analytics-migrations');
        }
    }
}