<?php

/**
 * Feature test for the BotnetService.
 * * This test suite ensures that the botnet detection logic correctly identifies
 * known signatures, handles caching/throttling, and detects new clusters
 * from raw visit logs.
 */

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

use Oleant\VisitAnalytics\Services\BotnetService;
use Oleant\VisitAnalytics\Models\BotnetFingerprint;
use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Support\Facades\Cache;

beforeEach(function () {
    /** @var BotnetService $this->service */
    $this->service = new BotnetService();
});

/**
 * @test
 * Verifies that the service generates a consistent SHA-256 hash for User-Agents.
 */
it('can generate a valid sha256 hash', function () {
    $ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    $expected = hash('sha256', $ua);
    
    expect($this->service->generateHash($ua))->toBe($expected);
});

/**
 * @test
 * Confirms that a User-Agent is correctly flagged if its hash exists in the botnet database.
 */
it('identifies a known botnet fingerprint', function () {
    $ua = 'Evil-Bot-1.0';
    BotnetFingerprint::create([
        'ua_hash' => hash('sha256', $ua),
        'user_agent' => $ua,
        'is_active' => true,
    ]);

    expect($this->service->isKnownBotnet($ua))->toBeTrue();
});

/**
 * @test
 * Ensures that the system throttles updates to the 'last_seen_at' timestamp 
 * by checking the internal cache before hitting the database.
 */
it('throttles the last_seen_at update', function () {
    // Mock the cache to prevent the service from updating the DB
    Cache::shouldReceive('has')->once()->andReturn(true);
    
    $ua = 'Evil-Bot-1.0';
    BotnetFingerprint::create([
        'ua_hash' => hash('sha256', $ua),
        'user_agent' => $ua,
    ]);

    $this->service->isKnownBotnet($ua);
});

/**
 * @test
 * Validates the cluster detection algorithm.
 * It simulates a distributed attack using a common User-Agent across multiple unique IPs.
 * Note: The UA must not contain 'bot' or other excluded keywords to pass the primary filter.
 */
it('detects new clusters based on hits and unique ips', function () {
    // Use a clean UA to bypass internal "NOT LIKE %bot%" exclusions
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36';
    
    // Create 55 logs (threshold is usually 50) 
    // distributed over 11 unique IPs (threshold is usually 10)
    for ($i = 1; $i <= 55; $i++) {
        VisitLog::create([
            'user_agent' => $ua,
            'ip_address' => "192.168.1." . ($i % 11),
            'url'        => 'https://example.com/test',
            'method'     => 'GET',
            'created_at' => now(),
        ]);
    }

    // Act: Run the detection logic
    $newCount = $this->service->detectNewClusters();
    
    // Assert: One new fingerprint should be created and stored in the database
    expect($newCount)->toBe(1)
        ->and(BotnetFingerprint::where('user_agent', $ua)->exists())->toBeTrue();
});