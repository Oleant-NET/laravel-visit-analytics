<?php

namespace Oleant\VisitAnalytics\Tests;

use Oleant\VisitAnalytics\VisitAnalyticsServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

/**
 * The base TestCase class for the package.
 * It sets up a virtual Laravel environment using Orchestra Testbench.
 */
class TestCase extends Orchestra
{
    /**
     * Set up the testing environment.
     * This runs before each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Additional setup like factory loading can be added here
    }

    /**
     * Register the package service provider.
     *
     * @param \Illuminate\Foundation\Application $app
     * @return array
     */
    protected function getPackageProviders($app)
    {
        return [
            VisitAnalyticsServiceProvider::class,
        ];
    }

    /**
     * Define environment setup.
     * We use an in-memory SQLite database for fast test execution.
     *
     * @param \Illuminate\Foundation\Application $app
     * @return void
     */
    protected function getEnvironmentSetUp($app)
    {
        // Setup default database to use sqlite :memory:
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        // Mocking some default config values if needed
        $app['config']->set('visit-analytics.table_name', 'visit_logs');
    }

    /**
     * Automatically run migrations for the testing database.
     *
     * @return void
     */
    protected function defineDatabaseMigrations()
    {
        // This will load and run your package's migrations in the SQLite memory
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }
}