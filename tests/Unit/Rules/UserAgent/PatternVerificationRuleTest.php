<?php

use Oleant\VisitAnalytics\Rules\UserAgent\PatternVerificationRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Oleant\VisitAnalytics\Tests\TestCase;

uses(TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new PatternVerificationRule();
    $this->state = new AnalysisState();
    $this->params = [
        'ua_regex_patterns' => [
            'reduced_ua' => [
                'pattern' => '/\d+\.0\.0\.0/', 
                'score'  => 20,
                'requires_verification' => true,
            ],
            'headless_chrome' => [
                'pattern' => '/HeadlessChrome/i',
                'score'  => 100,
                'requires_verification' => false,
            ],
        ],
    ];
});

it('adds penalty when deep verification fails', function () {
    // Chrome/120 present, but headers missing (verification failure)
    $log = VisitLog::factory()->create([
        'user_agent' => 'Mozilla/5.0 Chrome/120.0.0.0',
        'target_headers' => [] 
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(20)
        ->and($this->state->getReasons())->toContain('verification_failed_reduced_ua');
});

it('does not penalize when verification succeeds', function () {
    $log = VisitLog::factory()->create([
        'user_agent' => 'Mozilla/5.0 Chrome/120.0.0.0',
        'target_headers' => [
            'sec-ch-ua' => '"Chromium";v="120"',
            'sec-ch-ua-platform' => '"Windows"'
        ]
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});

it('handles raw regex patterns without delimiters correctly', function () {
    $params = [
        'ua_regex_patterns' => ['test' => 'SimpleBot']
    ];
    
    $log = VisitLog::factory()->create(['user_agent' => 'SimpleBot']);
    $this->rule->apply($log, $this->state, $params);

    expect($this->state->getScore())->toBe(0); // weight defaults to 0 if not provided
});