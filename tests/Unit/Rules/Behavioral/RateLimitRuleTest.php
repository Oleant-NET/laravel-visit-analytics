<?php

use Oleant\VisitAnalytics\Rules\Behavioral\RateLimitRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new RateLimitRule();
    $this->state = new AnalysisState();
    $this->params = [
        'rate_limit_per_minute' => 10,
        'time_window' => 1, // 1 minute window
        'weights' => ['rate' => 15]
    ];
});

test('it identifies high request rate anomaly', function () {
    $ip = '1.1.1.1';
    
    // Create 11 regular requests (limit is 10)
    for ($i = 0; $i < 11; $i++) {
        VisitLog::factory()->create([
            'ip_address' => $ip,
            'target_headers' => null, // Not an AJAX request
            'created_at' => now()->subSeconds(10),
        ]);
    }

    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'target_headers' => null,
        'created_at' => now(),
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(15)
        ->and($this->state->getReasons())->toContain('high_request_rate');
});

test('it ignores ajax requests in rate count', function () {
    $ip = '1.1.1.1';

    // 15 AJAX requests should not trigger the rule
    for ($i = 0; $i < 15; $i++) {
        VisitLog::factory()->create([
            'ip_address' => $ip,
            'target_headers' => ['x-requested-with' => 'XMLHttpRequest'],
            'created_at' => now()->subSeconds(5),
        ]);
    }

    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'target_headers' => null, // Current request is regular
        'created_at' => now(),
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});