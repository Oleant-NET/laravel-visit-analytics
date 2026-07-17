<?php

use Oleant\VisitAnalytics\Analyzers\ReputationAnalyzer;
use Oleant\VisitAnalytics\Analyzers\Rules\Reputation\RepeatOffenderRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

it('applies penalty for repeat offenders based on history', function () {
    $ip = '10.0.0.1';
    
    // Create 2 previous bot logs for this IP
    VisitLog::factory()->count(2)->create([
        'ip_address' => $ip,
        'is_bot' => true,
        'created_at' => now()->subHours(1)
    ]);

    $currentLog = VisitLog::factory()->create(['ip_address' => $ip]);
    $state = new AnalysisState();
    $analyzer = new ReputationAnalyzer();
    
    $params = [
        'rules' => [RepeatOffenderRule::class],
        'cumulative' => [
            'enabled' => true,
            'history_window_hours' => 24,
            'penalty_multiplier' => 15
        ]
    ];

    $analyzer->analyze($currentLog, $state, $params);

    // Expected: 2 offenses * 15 multiplier = 30
    expect($state->getScore())->toBe(30)
        ->and($state->getReasons())->toContain('repeat_offender')
        ->and($state->getEvidenceValue('repeat_offender'))->toBe([
            'past_offenses_count' => 2,
            'history_window' => '24h'
        ]);
});

it('does not apply penalty if cumulative is disabled', function () {
    $ip = '10.0.0.1';
    VisitLog::factory()->create(['ip_address' => $ip, 'is_bot' => true]);
    $log = VisitLog::factory()->create(['ip_address' => $ip]);

    $state = new AnalysisState();
    $analyzer = new ReputationAnalyzer();

    $analyzer->analyze($log, $state, [
        'rules' => [RepeatOffenderRule::class],
        'cumulative' => ['enabled' => false]
    ]);

    expect($state->getScore())->toBe(0);
});