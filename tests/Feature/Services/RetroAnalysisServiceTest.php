<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Services;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Services\RetroAnalysisService;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

beforeEach(function () {

    VisitLog::truncate();

    config([
        'visit-analytics.retro_analysis' => [

            'session_window' => 60,

            // Lower threshold for tests
            'burst_threshold' => 3,

            'lookback_minutes' => 15,
        ]
    ]);
});

/**
 * @test
 */
it('detects and flags rapid document request bursts', function () {

    $ip = '192.168.1.1';

    $ua = 'Mozilla/5.0 (Test Agent)';

    /**
     * Create document requests only.
     * Ajax/widget requests must NOT participate anymore.
     */
    VisitLog::factory()
        ->count(3)
        ->create([
            'ip_address' => $ip,

            'user_agent' => $ua,

            'is_bot' => false,

            'created_at' => now()->subMinutes(2),

            'target_headers' => [
                'sec-fetch-dest' => 'document',
            ],
        ]);

    $service = new RetroAnalysisService();

    $updatedCount = $service->handle();

    expect($updatedCount)->toBe(3);

    $logs = VisitLog::where('ip_address', $ip)->get();

    foreach ($logs as $log) {

        expect($log->is_bot)->toBeTrue();

        expect($log->bot_reasons)
            ->toContain('burst_density_exceeded');
    }
});

/**
 * @test
 */
it('does not count ajax widget bursts as suspicious traffic', function () {

    $ip = '192.168.1.2';

    VisitLog::factory()
        ->count(10)
        ->create([
            'ip_address' => $ip,

            'is_bot' => false,

            'created_at' => now()->subMinutes(1),

            // Vue/Ajax request
            'target_headers' => [
                'x-requested-with' => 'XMLHttpRequest',
                'sec-fetch-dest' => 'empty',
            ],
        ]);

    $service = new RetroAnalysisService();

    $updated = $service->handle();

    expect($updated)->toBe(0);

    expect(
        VisitLog::where('ip_address', $ip)
            ->where('is_bot', true)
            ->count()
    )->toBe(0);
});

/**
 * @test
 */
it('backfills preceding requests for confirmed bot IPs', function () {

    $ip = '1.2.3.4';

    /**
     * Clean earlier hit
     */
    $cleanLog = VisitLog::factory()->create([
        'ip_address' => $ip,

        'is_bot' => false,

        'created_at' => now()->subSeconds(30),

        'target_headers' => [
            'sec-fetch-dest' => 'document',
        ],
    ]);

    /**
     * Later confirmed bot
     */
    VisitLog::factory()->create([
        'ip_address' => $ip,

        'is_bot' => true,

        'bot_score' => 100,

        'processed_at' => now(),

        'created_at' => now(),

        'target_headers' => [
            'sec-fetch-dest' => 'document',
        ],
    ]);

    $service = new RetroAnalysisService();

    $service->handle();

    $cleanLog->refresh();

    expect($cleanLog->is_bot)->toBeTrue();

    expect($cleanLog->bot_reasons)
        ->toContain('retroactive_session_backfill');
});

/**
 * @test
 */
it('ignores logs outside of the lookback period', function () {

    config([
        'visit-analytics.retro_analysis.lookback_minutes' => 5
    ]);

    VisitLog::factory()
        ->count(5)
        ->create([
            'ip_address' => '8.8.8.8',

            'is_bot' => false,

            'created_at' => now()->subMinutes(10),

            'target_headers' => [
                'sec-fetch-dest' => 'document',
            ],
        ]);

    $service = new RetroAnalysisService();

    $updated = $service->handle();

    expect($updated)->toBe(0);
});

/**
 * @test
 */
it('appends reasons and evidence without overwriting existing data', function () {

    $log = VisitLog::factory()->create([
        'ip_address' => '9.9.9.9',

        'is_bot' => false,

        'bot_reasons' => [
            'initial_reason'
        ],

        'bot_evidence' => [
            'initial' => 'data'
        ],

        'created_at' => now()->subMinutes(1),

        'target_headers' => [
            'sec-fetch-dest' => 'document',
        ],
    ]);

    VisitLog::factory()
        ->count(3)
        ->create([
            'ip_address' => '9.9.9.9',

            'user_agent' => $log->user_agent,

            'is_bot' => false,

            'created_at' => now()->subMinutes(1),

            'target_headers' => [
                'sec-fetch-dest' => 'document',
            ],
        ]);

    $service = new RetroAnalysisService();

    $service->handle();

    $log->refresh();

    expect($log->bot_reasons)
        ->toContain('initial_reason');

    expect($log->bot_reasons)
        ->toContain('burst_density_exceeded');

    expect($log->bot_evidence)
        ->toHaveKey('initial');

    expect($log->bot_evidence)
        ->toHaveKey('retro_burst');
});

/**
 * @test
 */
it('does not backfill unrelated historical traffic', function () {

    $ip = '11.11.11.11';

    /**
     * Old request outside session window
     */
    $oldLog = VisitLog::factory()->create([
        'ip_address' => $ip,

        'is_bot' => false,

        'created_at' => now()->subMinutes(5),

        'target_headers' => [
            'sec-fetch-dest' => 'document',
        ],
    ]);

    /**
     * Recent confirmed bot
     */
    VisitLog::factory()->create([
        'ip_address' => $ip,

        'is_bot' => true,

        'bot_score' => 100,

        'processed_at' => now(),

        'created_at' => now(),
    ]);

    $service = new RetroAnalysisService();

    $service->handle();

    $oldLog->refresh();

    expect($oldLog->is_bot)->toBeFalse();
});

/**
 * @test
 */
it('logs errors but returns 0 if an exception occurs', function () {

    config([
        'visit-analytics.retro_analysis.lookback_minutes' => 'invalid'
    ]);

    $service = new RetroAnalysisService();

    $result = $service->handle();

    expect($result)->toBe(0);
});