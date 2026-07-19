<?php

use Oleant\VisitAnalytics\Rules\Reputation\RepeatOffenderRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new RepeatOffenderRule();
    $this->state = new AnalysisState();
    $this->params = [
        'cumulative' => [
            'enabled' => true,
            'history_window_hours' => 24,
            'penalty_multiplier' => 10
        ]
    ];
});

it('adds penalty when IP has previous bot offenses', function () {
    $ip = '192.168.1.100';

    // Create 3 previous offenses
    VisitLog::factory()->count(3)->create([
        'ip_address' => $ip,
        'is_bot' => true,
        'created_at' => now()->subHours(2)
    ]);

    $log = VisitLog::factory()->create(['ip_address' => $ip]);

    $this->rule->apply($log, $this->state, $this->params);

    // Score: 3 offenses * 10 multiplier = 30
    expect($this->state->getScore())->toBe(30)
        ->and($this->state->getReasons())->toContain('repeat_offender')
        ->and($this->state->getEvidenceValue('repeat_offender'))->toBe([
            'past_offenses_count' => 3,
            'history_window' => '24h'
        ]);
});

it('does not penalize if no previous offenses exist', function () {
    $log = VisitLog::factory()->create(['ip_address' => '1.1.1.1']);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0)
        ->and($this->state->getReasons())->toBeEmpty();
});

it('respects the history window', function () {
    $ip = '192.168.1.100';

    // Create an offense outside the 24h window (e.g., 48 hours ago)
    VisitLog::factory()->create([
        'ip_address' => $ip,
        'is_bot' => true,
        'created_at' => now()->subHours(48)
    ]);

    $log = VisitLog::factory()->create(['ip_address' => $ip]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});

it('ignores offenses with a higher or equal log id', function () {
    $ip = '192.168.1.100';

    // 1. Current log with ID 10
    $log = VisitLog::factory()->create([
        'id' => 10,
        'ip_address' => $ip
    ]);

    // 2. "Future" offense with ID 11
    VisitLog::factory()->create([
        'id' => 11,
        'ip_address' => $ip,
        'is_bot' => true,
        'created_at' => now()->subMinutes(10)
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    // Score should be 0 because the only offense has ID 11, which is not < 10
    expect($this->state->getScore())->toBe(0);
});