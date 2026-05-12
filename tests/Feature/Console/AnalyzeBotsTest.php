<?php

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Models\BotnetFingerprint;
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
 * It uses a known honeypot path to ensure the 'is_bot' status is correctly updated.
 */
it('updates bot status after command execution', function () {
    // Create a visit to a sensitive path that should trigger bot detection
    $log = VisitLog::create([
        'ip_address' => '3.3.3.3',
        'user_agent' => 'EvilBot',
        'url' => '/.env', 
        'processed_at' => null
    ]);

    $this->artisan('visit-analytics:analyze-bots');

    $log->refresh();
    
    // Assert that the visit was processed and correctly flagged as a bot
    expect($log->processed_at)->not->toBeNull()
        ->and($log->is_bot)->toBeTrue();
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
 * Verifies that the command anonymizes the IP address in async mode.
 */
it('anonymizes the ip address when running in async mode', function () {
    // 1. Set config to async mode
    config([
        'visit-analytics.collection.anonymize_ip' => true,
        'visit-analytics.collection.anonymize_mode' => 'async'
    ]);

    // 2. Create a log with a full IP
    $log = VisitLog::create([
        'ip_address' => '1.2.3.4',
        'user_agent' => 'Test',
        'url' => '/',
        'processed_at' => null
    ]);

    // 3. Execute the command
    $this->artisan('visit-analytics:analyze-bots');

    // 4. Assert the IP is now anonymized in the database
    $log->refresh();
    expect($log->ip_address)->toBe('1.2.3.0');
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

/**
 * @test
 * Verifies that the command processes pending logs and successfully 
 * identifies new botnet clusters based on traffic patterns.
 */
it('processes logs and triggers botnet cluster detection', function () {
    /**
     * 1. Setup: Prepare a 'clean' log entry that should be marked as processed.
     */
    VisitLog::create([
        'ip_address' => '1.1.1.1',
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
        'url'        => 'https://example.com/home',
        'method'     => 'GET',
        'processed_at' => null
    ]);

    /**
     * 2. Setup: Prepare a suspicious cluster (55 visits from 11 unique IPs).
     * We use a specific UA to trigger the cluster detection logic.
     */
    $ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36';
    for ($i = 1; $i <= 55; $i++) {
        VisitLog::create([
            'ip_address' => "2.2.2." . ($i % 11),
            'user_agent' => $ua,
            'url'        => 'https://example.com/login',
            'method'     => 'POST',
            'processed_at' => now() // Cluster detection usually looks at processed logs
        ]);
    }

    /**
     * 3. Action: Execute the bot analysis command.
     */
    Artisan::call('visit-analytics:analyze-bots');

    /**
     * 4. Assert: Ensure all pending logs are now marked as processed.
     */
    expect(VisitLog::whereNull('processed_at')->count())->toBe(0);
    
    /**
     * 5. Assert: Verify that the new botnet fingerprint was detected and stored.
     */
    expect(BotnetFingerprint::where('user_agent', $ua)->exists())->toBeTrue();
});

/**
 * @test
 * Confirms that the command does not create duplicate fingerprints 
 * if the same cluster is detected again.
 */
it('does not create duplicate fingerprints for existing botnets', function () {
    $ua = 'Persistent-Botnet-UA/1.0';
    
    // Pre-seed the database with an existing fingerprint
    BotnetFingerprint::create([
        'ua_hash' => hash('sha256', $ua),
        'user_agent' => $ua,
        'is_active' => true
    ]);

    // Create logs that would normally trigger a new cluster detection
    for ($i = 1; $i <= 55; $i++) {
        VisitLog::create([
            'ip_address' => "3.3.3." . ($i % 11),
            'user_agent' => $ua,
            'url'        => 'https://example.com/api',
            'method'     => 'GET',
            'processed_at' => now()
        ]);
    }

    Artisan::call('visit-analytics:analyze-bots');

    // Ensure we still have only one record for this UA
    expect(BotnetFingerprint::where('user_agent', $ua)->count())->toBe(1);
});