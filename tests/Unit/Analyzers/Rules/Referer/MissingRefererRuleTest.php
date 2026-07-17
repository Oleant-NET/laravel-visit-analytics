<?php

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Analyzers\Rules\Referer\MissingRefererRule;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);
uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new MissingRefererRule();
});

it('penalizes missing referer when fetch-site is null', function () {
    $state = new AnalysisState();
    $log = VisitLog::factory()->create(['referer' => null, 'target_headers' => []]);

    $this->rule->apply($log, $state, ['weights' => ['no_referer' => 40]]);

    expect($state->getScore())->toBe(40)
        ->and($state->getReasons())->toContain('missing_referer');
});

it('penalizes suspicious navigation even if fetch-site is present', function () {
    $ip = '1.2.3.4';
    $state = new AnalysisState();
    
    // Create a previous visit to make this NOT an "initial direct hit"
    VisitLog::factory()->create([
        'ip_address' => $ip, 
        'target_headers' => ['sec-fetch-site' => 'same-origin'],
        'created_at' => now()->subMinute()
    ]);

    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'referer' => null,
        'target_headers' => ['sec-fetch-site' => 'same-origin']
    ]);

    $this->rule->apply($log, $state, ['weights' => ['no_referer' => 50]]);

    expect($state->getScore())->toBe(50)
        ->and($state->getReasons())->toContain('missing_referer_on_navigation');
});

it('ignores initial direct hit navigation', function () {
    $ip = '1.2.3.4';
    $state = new AnalysisState();
    
    // First hit in session, fetch-site is 'none'
    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'referer' => null,
        'target_headers' => ['sec-fetch-site' => 'none']
    ]);

    $this->rule->apply($log, $state, []);

    expect($state->getScore())->toBe(0);
});

it('calculates snowball penalty for repeated direct hits', function () {
    $ip = '1.2.3.4';
    $state = new AnalysisState();

    // Setup: 2 direct hits in the window
    VisitLog::factory()->count(2)->create([
        'ip_address' => $ip,
        'referer' => null,
        'target_headers' => ['sec-fetch-site' => 'none']
    ]);

    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'referer' => null,
        'target_headers' => ['sec-fetch-site' => 'none']
    ]);

    $params = [
        'cumulative' => [
            'enabled' => true, 
            'no_referer_increment' => 20
        ]
    ];

    $this->rule->apply($log, $state, $params);

    // Expect: 2 previous hits * 20 penalty = 40
    expect($state->getScore())->toBe(40)
        ->and($state->getReasons())->toContain('referer_snowball')
        ->and($state->getEvidenceValue('referer_snowball'))->toBe(['sequential_direct_hits' => 2]);
});