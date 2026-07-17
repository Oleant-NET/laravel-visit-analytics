<?php

use Oleant\VisitAnalytics\Analyzers\Rules\Behavioral\UserAgentStabilityRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new UserAgentStabilityRule();
    $this->state = new AnalysisState();
    $this->params = [
        'ua_stability_window' => 30,
        'weights' => ['ua_change_anomaly' => 40]
    ];
});

test('it does not penalize if user-agent is consistent', function () {
    $ip = '1.1.1.1';
    $ua = 'Mozilla/5.0';

    VisitLog::factory()->create(['ip_address' => $ip, 'user_agent' => $ua]);
    $log = VisitLog::factory()->create(['ip_address' => $ip, 'user_agent' => $ua]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});

test('it penalizes if user-agent changes within stability window', function () {
    $ip = '1.1.1.1';
    $oldUa = 'Mozilla/5.0 (Windows)';
    $newUa = 'Mozilla/5.0 (Linux)';

    VisitLog::factory()->create(['ip_address' => $ip, 'user_agent' => $oldUa, 'created_at' => now()->subMinutes(5)]);
    $log = VisitLog::factory()->create(['ip_address' => $ip, 'user_agent' => $newUa, 'created_at' => now()]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(40)
        ->and($this->state->getReasons())->toContain('ua_change_anomaly')
        ->and($this->state->getEvidence()['ua_change_anomaly'])->toHaveKey('previous_ua', $oldUa)
        ->and($this->state->getEvidence()['ua_change_anomaly'])->toHaveKey('current_ua', $newUa);
});

test('it ignores change if it happened outside the window', function () {
    $ip = '1.1.1.1';
    
    // Change happened 60 minutes ago (window is 30)
    VisitLog::factory()->create(['ip_address' => $ip, 'user_agent' => 'UA-1', 'created_at' => now()->subMinutes(60)]);
    $log = VisitLog::factory()->create(['ip_address' => $ip, 'user_agent' => 'UA-2', 'created_at' => now()]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});