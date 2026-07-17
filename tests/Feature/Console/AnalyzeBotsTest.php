<?php

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Support\Facades\Artisan;

/**
 * Setup the test environment before each test.
 * Clears the visit logs to ensure a clean state.
 */
beforeEach(function () {
    VisitLog::truncate();
});

/**
 * @test
 * Verifies that the command only processes records where 'processed_at' is null.
 * It ensures that already analyzed visits are not re-processed.
 */
it('processes only unprocessed visits', function () {
    // 1. Create a visit that is already marked as processed
    VisitLog::create([
        'ip_address' => '1.1.1.1',
        'user_agent' => 'Mozilla',
        'url' => '/',
        'processed_at' => now()->subDay(),
        'is_bot' => false
    ]);

    // 2. Create a new unprocessed visit
    VisitLog::create([
        'ip_address' => '2.2.2.2',
        'user_agent' => 'Bot',
        'url' => '/',
        'processed_at' => null
    ]);

    // Execute the analyze-bots command
    $this->artisan('visit-analytics:analyze-bots')
         ->assertExitCode(0);

    // Assert that there are no unprocessed records left in the database
    expect(VisitLog::whereNull('processed_at')->count())->toBe(0);
});

/**
 * @test
 * Verifies that the --max option correctly limits the number of processed records.
 * This is crucial for controlling performance and resource usage.
 */
it('respects the max limit option', function () {
    // Create 10 unprocessed visits manually without a factory
    foreach (range(1, 10) as $i) {
        VisitLog::create([
            'ip_address' => "1.1.1.$i",
            'user_agent' => 'TestAgent',
            'url' => '/',
            'processed_at' => null
        ]);
    }

    // Attempt to process only 4 visits using the --max option
    $this->artisan('visit-analytics:analyze-bots', ['--max' => 4]);

    // Assert that exactly 4 records were processed and 6 remain unprocessed
    expect(VisitLog::whereNotNull('processed_at')->count())->toBe(4);
    expect(VisitLog::whereNull('processed_at')->count())->toBe(6);
});

/**
 * @test
 * Confirms that the command triggers the underlying analysis logic.
 */
it('updates bot status after command execution', function () {
    // 1. Create a mock analyzer that forces a "bot" verdict
    $mockAnalyzer = Mockery::mock(\Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface::class);
    $mockAnalyzer->shouldReceive('analyze')
        ->once()
        ->andReturnUsing(function ($log, $state) {
            $state->score = 100; // Force bot status
            $state->reasons[] = 'Honeypot hit';
        });

    // 2. Register mock in the container
    app()->instance('ForcedBotAnalyzer', $mockAnalyzer);

    // 3. Configure the command to use this mock
    config(['visit-analytics.detection_engine' => [
        'threshold' => 70,
        'analyzers' => [
            [
                'class' => 'ForcedBotAnalyzer',
                'enabled' => true,
                'params' => []
            ]
        ]
    ]]);

    // 4. Create the log entry
    $log = VisitLog::create([
        'ip_address' => '3.3.3.3',
        'user_agent' => 'EvilBot',
        'url' => '/.env',
        'processed_at' => null
    ]);

    // 5. Execute command
    $this->artisan('visit-analytics:analyze-bots');

    // 6. Assertions
    $log->refresh();
    
    expect($log->processed_at)->not->toBeNull()
        ->and($log->is_bot)->toBeTrue()
        ->and($log->bot_reasons)->toContain('Honeypot hit');
});

/**
 * @test
 * Verifies that the command runs successfully when the --full reporting flag is enabled.
 * This ensures the reporting logic doesn't crash the command.
 */
it('provides output when --full flag is used', function () {
    VisitLog::create([
        'ip_address' => '4.4.4.4',
        'user_agent' => 'Test',
        'url' => '/',
    ]);

    // Execute the command with the --full flag and assert successful exit
    $exitCode = Artisan::call('visit-analytics:analyze-bots', ['--full' => true]);
    
    expect($exitCode)->toBe(0);
});

/**
 * @test
 * Verifies that the command leaves the IP intact if anonymize_ip is disabled.
 */
it('does not anonymize the ip if the feature is disabled', function () {
    config(['visit-analytics.collection.anonymize_ip' => false]);

    $log = VisitLog::create([
        'ip_address' => '1.2.3.4',
        'user_agent' => 'Test',
        'url' => '/',
        'processed_at' => null
    ]);

    $this->artisan('visit-analytics:analyze-bots');

    $log->refresh();
    expect($log->ip_address)->toBe('1.2.3.4');
});
