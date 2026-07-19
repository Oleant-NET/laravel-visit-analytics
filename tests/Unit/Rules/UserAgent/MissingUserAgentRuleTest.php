<?php

use Oleant\VisitAnalytics\Rules\UserAgent\MissingUserAgentRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new MissingUserAgentRule();
    $this->state = new AnalysisState();
    $this->params = [
        'score' => 100,
    ];
});

it('adds penalty when user-agent is null or empty', function ($uaValue) {
    $log = VisitLog::factory()->create(['user_agent' => $uaValue]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(100)
        ->and($this->state->getReasons())->toContain('missing_user_agent')
        ->and($this->state->getEvidenceValue('missing_user_agent'))->toBe(['ua_status' => 'empty_header']);
})->with([
    null,
    '',
    '   ' // Test trimming logic
]);

it('does not add penalty when user-agent is present', function () {
    $log = VisitLog::factory()->create([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0)
        ->and($this->state->getReasons())->toBeEmpty();
});

it('uses default penalty if weight is not configured', function () {
    $log = VisitLog::factory()->create(['user_agent' => '']);

    // Call without 'weights' in params
    $this->rule->apply($log, $this->state, []);

    // 100 is the hardcoded fallback in the rule
    expect($this->state->getScore())->toBe(100);
});