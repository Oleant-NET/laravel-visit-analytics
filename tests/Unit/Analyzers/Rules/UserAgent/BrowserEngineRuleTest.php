<?php

use Oleant\VisitAnalytics\Analyzers\Rules\UserAgent\BrowserEngineRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new BrowserEngineRule();
    $this->state = new AnalysisState();
    $this->params = [
        'browser_engines' => ['Gecko', 'Blink', 'Trident', 'AppleWebKit'],
        'weights' => [
            'ua_suspicious' => 50
        ]
    ];
});

it('does not penalize when a valid browser engine is present', function ($ua) {
    $log = VisitLog::factory()->create(['user_agent' => $ua]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0)
        ->and($this->state->getReasons())->toBeEmpty();
})->with([
    'Mozilla/5.0 (Windows NT 10.0; Gecko/20100101 Firefox/120.0)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (compatible; MSIE 10.0; Trident/6.0)'
]);

it('adds penalty when no valid browser engine is found', function () {
    $log = VisitLog::factory()->create([
        'user_agent' => 'MyCustomBot/1.0 (NoEngineDetected)'
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(50)
        ->and($this->state->getReasons())->toContain('ua_suspicious')
        ->and($this->state->getEvidenceValue('ua_suspicious'))->toBe(['reason' => 'missing_browser_engine']);
});

it('uses default penalty if weight is missing', function () {
    $log = VisitLog::factory()->create(['user_agent' => 'Unknown/1.0']);

    $this->rule->apply($log, $this->state, [
        'browser_engines' => ['Gecko']
    ]);

    // 50 is the hardcoded fallback
    expect($this->state->getScore())->toBe(50);
});

it('handles empty browser engine list gracefully', function () {
    $log = VisitLog::factory()->create(['user_agent' => 'Mozilla/5.0 (Any)']);
    
    // If no engines are defined in config, it should treat as suspicious
    $this->rule->apply($log, $this->state, ['browser_engines' => []]);

    expect($this->state->getScore())->toBe(50);
});