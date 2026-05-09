<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\ReputationAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

/**
 * @test
 * Verifies that the analyzer skips processing if the cumulative 
 * reputation check is disabled in the configuration.
 */
it('skips analysis when cumulative reputation is disabled', function () {
    $ip = '1.2.3.4';
    
    // Create a past offense
    VisitLog::factory()->create([
        'ip_address' => $ip,
        'is_bot' => true,
        'created_at' => now()->subHour()
    ]);

    $log = VisitLog::factory()->create(['ip_address' => $ip]);
    $state = new AnalysisState();
    $analyzer = new ReputationAnalyzer();

    $analyzer->analyze($log, $state, ['cumulative' => ['enabled' => false]]);

    expect($state->getScore())->toBe(0);
});

/**
 * @test
 * Confirms that an IP address with previous bot detections 
 * receives a penalty based on the offense count and multiplier.
 */
it('penalizes repeat offenders based on past detections', function () {
    $ip = '10.0.0.1';
    $hours = 24;
    $multiplier = 15;

    // 1. Seed 3 past offenses within the window
    VisitLog::factory()->count(3)->create([
        'ip_address' => $ip,
        'is_bot' => true,
        'created_at' => now()->subHours(2)
    ]);

    // 2. Seed 1 offense outside the window (should be ignored)
    VisitLog::factory()->create([
        'ip_address' => $ip,
        'is_bot' => true,
        'created_at' => now()->subHours($hours + 1)
    ]);

    $currentLog = VisitLog::factory()->create(['ip_address' => $ip]);
    $state = new AnalysisState();
    $analyzer = new ReputationAnalyzer();
    
    $params = [
        'cumulative' => [
            'enabled' => true,
            'history_window_hours' => $hours,
            'penalty_multiplier' => $multiplier
        ]
    ];

    $analyzer->analyze($currentLog, $state, $params);

    // Score: 3 offenses * 15 points = 45
    expect($state->getScore())->toBe(45)
        ->and($state->getReasons())->toContain('repeat_offender')
        ->and($state->getEvidence())->toMatchArray([
            'past_offenses_count' => 3,
            'history_window' => "{$hours}h"
        ]);
});

/**
 * @test
 * Ensures that legitimate previous visits (is_bot = false) 
 * do not contribute to the reputation penalty.
 */
it('does not penalize for past legitimate visits', function () {
    $ip = '192.168.1.1';

    // Create 5 legitimate visits
    VisitLog::factory()->count(5)->create([
        'ip_address' => $ip,
        'is_bot' => false,
        'created_at' => now()->subHour()
    ]);

    $currentLog = VisitLog::factory()->create(['ip_address' => $ip]);
    $state = new AnalysisState();
    $analyzer = new ReputationAnalyzer();
    
    $params = [
        'cumulative' => ['enabled' => true]
    ];

    $analyzer->analyze($currentLog, $state, $params);

    expect($state->getScore())->toBe(0);
});

/**
 * @test
 * Verifies that the analyzer skips execution if the IP address is missing.
 */
it('skips analysis if ip_address is missing', function () {
    $log = VisitLog::factory()->make(['ip_address' => null]);
    $state = new AnalysisState();
    $analyzer = new ReputationAnalyzer();

    $analyzer->analyze($log, $state, ['cumulative' => ['enabled' => true]]);

    expect($state->getScore())->toBe(0);
});

/**
 * @test
 * Ensures the analyzer only counts records created before the current log ID.
 */
it('only counts offenses that occurred before the current log', function () {
    $ip = '5.5.5.5';
    
    // Create current log first
    $currentLog = VisitLog::factory()->create(['ip_address' => $ip]);
    
    // Create a "future" offense (higher ID)
    VisitLog::factory()->create([
        'ip_address' => $ip,
        'is_bot' => true,
        'created_at' => now()->subMinutes(1) 
    ]);

    $state = new AnalysisState();
    $analyzer = new ReputationAnalyzer();
    
    $analyzer->analyze($currentLog, $state, [
        'cumulative' => ['enabled' => true]
    ]);

    expect($state->getScore())->toBe(0);
});