<?php

use Oleant\VisitAnalytics\Analyzers\Rules\Behavioral\HeaderSetStabilityRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new HeaderSetStabilityRule();
    $this->state = new AnalysisState();
    $this->params = [
        'header_stability_window' => 30,
        'exclude_dynamic_headers' => ['sec-fetch-site'],
        'weights' => ['header_set_anomaly' => 30]
    ];
});

test('it penalizes when critical headers are lost', function () {
    $ip = '1.1.1.1';
    
    // Previous request contained 'accept-language'
    VisitLog::factory()->create([
        'ip_address' => $ip, 
        'target_headers' => ['accept-language' => 'en-US', 'sec-fetch-site' => 'same-origin'],
        'created_at' => now()->subMinutes(5)
    ]);

    // Current request lost the 'accept-language' header
    $log = VisitLog::factory()->create([
        'ip_address' => $ip, 
        'target_headers' => ['sec-fetch-site' => 'cross-site']
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    // Verify the anomaly score and evidence grouping
    expect($this->state->getScore())->toBe(30)
        ->and($this->state->getReasons())->toContain('header_set_anomaly')
        ->and($this->state->getEvidence())->toHaveKey('header_set_anomaly')
        ->and($this->state->getEvidence()['header_set_anomaly'])->toHaveKey('lost_headers', ['accept-language']);
});

test('it ignores ignored dynamic headers', function () {
    $ip = '1.1.1.1';
    
    // Previous request contained a dynamic header
    VisitLog::factory()->create([
        'ip_address' => $ip, 
        'target_headers' => ['sec-fetch-site' => 'same-origin']
    ]);

    // Current request lost only the dynamic header which is ignored by config
    $log = VisitLog::factory()->create([
        'ip_address' => $ip, 
        'target_headers' => []
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    // No penalty expected for dynamic header loss
    expect($this->state->getScore())->toBe(0);
});