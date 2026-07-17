<?php

use Oleant\VisitAnalytics\Analyzers\Rules\Behavioral\SpeedAnomalyRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new SpeedAnomalyRule();
    $this->state = new AnalysisState();
    $this->params = [
        'min_interval_ms' => 500, // 500ms threshold
        'weights' => ['speed_anomaly' => 10]
    ];
});

test('it does not penalize the first fast request', function () {
    $prev = VisitLog::factory()->create(['created_at' => now()->subMilliseconds(100)]);
    $log = VisitLog::factory()->create(['ip_address' => $prev->ip_address, 'created_at' => now()]);

    $this->rule->apply($log, $this->state, $this->params);

    // Should detect interval but not penalize yet (previous was not fast)
    expect($this->state->getScore())->toBe(0);
});

test('it penalizes if consecutive requests are fast', function () {
    $ip = '1.1.1.1';
    
    // First request already marked as 'speed_anomaly'
    $prev = VisitLog::factory()->create([
        'ip_address' => $ip,
        'bot_reasons' => ['speed_anomaly'],
        'created_at' => now()->subMilliseconds(100)
    ]);
    
    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'created_at' => now()
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(10)
        ->and($this->state->getReasons())->toContain('speed_anomaly');
});

test('it ignores ajax requests for speed calculation', function () {
    $prev = VisitLog::factory()->create([
        'target_headers' => ['x-requested-with' => 'XMLHttpRequest'],
        'created_at' => now()->subMilliseconds(100)
    ]);
    
    $log = VisitLog::factory()->create([
        'ip_address' => $prev->ip_address,
        'target_headers' => null,
        'created_at' => now()
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});