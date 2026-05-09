<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\HoneypotAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * @test
 * Verifies that visiting a forbidden path (trap) results 
 * in the appropriate penalty points being added to the state.
 */
it('flags visits to defined honeypot paths', function () {
    $log = VisitLog::factory()->make([
        'url' => 'https://example.com/.env'
    ]);

    $state = new AnalysisState();
    $analyzer = new HoneypotAnalyzer();
    
    $params = [
        'honeypot_paths' => ['.env', 'wp-admin', 'config.php'],
        'weights' => ['honeypot' => 100]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(100)
        ->and($state->getReasons())->toContain('honeypot_trap')
        ->and($state->getEvidence())->toHaveKey('matched_trap', '.env')
        ->and($state->getEvidence())->toHaveKey('honeypot_url', 'https://example.com/.env');
});

/**
 * @test
 * Ensures that the analyzer identifies the trap even if it is 
 * just a fragment within a longer or complex URL.
 */
it('detects honeypot paths as fragments within the URL', function () {
    $log = VisitLog::factory()->make([
        'url' => 'https://example.com/backup/v1/config.php?id=123'
    ]);

    $state = new AnalysisState();
    $analyzer = new HoneypotAnalyzer();
    
    $params = [
        'honeypot_paths' => ['config.php'],
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('honeypot_trap');
});

/**
 * @test
 * Confirms that legitimate paths do not trigger any bot flags or scores.
 */
it('does not flag legitimate paths', function () {
    $log = VisitLog::factory()->make([
        'url' => 'https://example.com/about-us'
    ]);

    $state = new AnalysisState();
    $analyzer = new HoneypotAnalyzer();
    
    $params = [
        'honeypot_paths' => ['.env', 'wp-login'],
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0)
        ->and($state->getReasons())->toBeEmpty();
});

/**
 * @test
 * Validates that the analyzer handles empty configuration without errors.
 */
it('handles empty honeypot configuration gracefully', function () {
    $log = VisitLog::factory()->make(['url' => 'https://example.com/any-path']);
    $state = new AnalysisState();
    $analyzer = new HoneypotAnalyzer();

    $analyzer->analyze($log, $state, ['honeypot_paths' => []]);

    expect($state->getScore())->toBe(0);
});

/**
 * @test
 * Ensures the analyzer stops execution (breaks the loop) after 
 * the first matched trap is found to prevent duplicate scoring.
 */
it('stops analysis after the first matched trap', function () {
    $log = VisitLog::factory()->make([
        'url' => 'https://example.com/admin/db.sql'
    ]);

    $state = new AnalysisState();
    $analyzer = new HoneypotAnalyzer();
    
    // The URL contains both 'admin' and 'db.sql'
    $params = [
        'honeypot_paths' => ['admin', 'db.sql'],
        'weights' => ['honeypot' => 100]
    ];

    $analyzer->analyze($log, $state, $params);

    // Should only have one reason and one score entry
    expect($state->getScore())->toBe(100)
        ->and($state->getReasons())->toHaveCount(1);
});