<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\RefererAnalyzer;
use Oleant\VisitAnalytics\Analyzers\Rules\Referer\MissingRefererRule;
use Oleant\VisitAnalytics\Analyzers\Rules\Referer\PortLeakRule;
use Oleant\VisitAnalytics\Analyzers\Rules\Referer\SelfRefererRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

/**
 * Define the standard rule set used across most referer analysis scenarios.
 */
beforeEach(function () {
    $this->defaultRules = [
        MissingRefererRule::class,
        PortLeakRule::class,
        SelfRefererRule::class,
    ];
});

/**
 * @test
 * Verifies that a base penalty is applied when the Referer header is missing.
 */
it('penalizes missing referer for direct navigation', function () {
    $log = VisitLog::factory()->create(['referer' => null]);
    $state = new AnalysisState();
    $analyzer = new RefererAnalyzer();
    
    $params = [
        'rules' => $this->defaultRules,
        'weights' => ['no_referer' => 35],
        'cumulative' => ['enabled' => false]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(35)
        ->and($state->getReasons())->toContain('missing_referer');
});

/**
 * @test
 * Verifies the "snowball" effect where repeated direct hits from the same IP 
 * increase the threat score cumulatively.
 */
it('applies cumulative penalty for sequential direct hits', function () {
    $ip = '192.168.1.1';
    
    // Setup: 2 previous direct hits within the last 5 minutes
    VisitLog::factory()->count(2)->create([
        'ip_address' => $ip,
        'referer' => null,
        'created_at' => now()->subMinutes(2)
    ]);

    $currentLog = VisitLog::factory()->create([
        'ip_address' => $ip,
        'referer' => null
    ]);

    $state = new AnalysisState();
    $analyzer = new RefererAnalyzer();
    
    $params = [
        'rules' => $this->defaultRules,
        'weights' => ['no_referer' => 10],
        'cumulative' => [
            'enabled' => true,
            'no_referer_window_minutes' => 10,
            'no_referer_increment' => 20
        ]
    ];

    $analyzer->analyze($currentLog, $state, $params);

    // Calculation: 10 (base) + (2 previous hits * 20 increment) = 50
    expect($state->getScore())->toBe(50)
        ->and($state->getReasons())->toContain('referer_snowball')
        ->and($state->getEvidenceValue('referer_snowball'))->toBe(['sequential_direct_hits' => 2]);
});

/**
 * @test
 * Checks for Referer headers that leak specific hosting panel ports.
 */
it('detects referer port leaks from hosting panels', function () {
    $log = VisitLog::factory()->create([
        'referer' => 'https://myserver.com:8443/config/manager'
    ]);

    $state = new AnalysisState();
    $analyzer = new RefererAnalyzer();
    
    $params = [
        'rules' => [$this->defaultRules[1]], // Run only PortLeakRule
        'port_leak' => [8443],
        'weights' => ['port_leak' => 45]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(45)
        ->and($state->getEvidenceValue('port_leak'))->toBe(['leaked_port' => 8443]);
});

/**
 * @test
 * Verifies that a critical anomaly is flagged if a page refers to itself 
 * on the very first visit from an IP.
 */
it('flags impossible self-referer loops on first visit', function () {
    $url = 'https://example.com/target-page';
    
    $log = VisitLog::factory()->create([
        'url' => $url,
        'referer' => $url,
        'ip_address' => '1.2.3.4'
    ]);

    $state = new AnalysisState();
    $analyzer = new RefererAnalyzer();
    
    $analyzer->analyze($log, $state, [
        'rules' => [$this->defaultRules[2]] // Run only SelfRefererRule
    ]);

    expect($state->getScore())->toBe(100)
        ->and($state->getReasons())->toContain('impossible_self_referer');
});

/**
 * @test
 * Verifies that a standard loop penalty is applied if the user has 
 * actually visited the page before.
 */
it('penalizes standard referer loops for returning visitors', function () {
    $ip = '5.5.5.5';
    $url = 'https://example.com/home';

    // First visit (legitimate)
    VisitLog::factory()->create(['ip_address' => $ip, 'url' => $url]);

    // Second visit (suspicious loop)
    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'url' => $url,
        'referer' => $url
    ]);

    $state = new AnalysisState();
    $analyzer = new RefererAnalyzer();
    
    $params = [
        'rules' => [$this->defaultRules[2]],
        'weights' => ['referer_loop' => 50]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(50)
        ->and($state->getReasons())->toContain('referer_loop');
});

/**
 * @test
 * Confirms that same-origin requests (e.g. AJAX) are ignored even if URL == Referer
 */
it('does not penalize same-origin requests that refer to themselves', function () {
    $url = 'https://example.com/api/data';
    
    $log = VisitLog::factory()->create([
        'url' => $url,
        'referer' => $url,
        'target_headers' => ['sec-fetch-site' => 'same-origin']
    ]);

    $state = new AnalysisState();
    $analyzer = new RefererAnalyzer();
    
    $analyzer->analyze($log, $state, ['rules' => [$this->defaultRules[2]]]);

    expect($state->getScore())->toBe(0);
});