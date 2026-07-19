<?php

use Oleant\VisitAnalytics\Rules\OutdatedBrowser\OutdatedBrowserRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

beforeEach(function () {
    $this->rule = new OutdatedBrowserRule();
    $this->state = new AnalysisState();
    
    // Default params for testing
    $this->params = [
        'current_versions' => ['chrome' => 120],
        'scoring' => [
            'minor_lag' => [
                'diff'        => 5,
                'score'       => 10,
            ],
            'moderate_lag' => [
                'diff'        => 10,
                'score'       => 25,
            ],
            'ancient_lag' => [
                'diff'        => 20,
                'score'       => 50,
            ],
        ],
    ];
});

it('applies a penalty when the browser version is outdated', function () {
    $log = new VisitLog([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(10)
        ->and($this->state->getEvidenceValue('outdated_browser'))->toMatchArray([
            'browser' => 'chrome',
            'version_lag' => 5,
            'severity_level' => 'minor_lag'
        ]);
});

it('applies the highest severity penalty for ancient browsers', function () {
    $log = new VisitLog([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36'
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    // Diff 20 triggers 'ancient_lag' (score 50)
    expect($this->state->getScore())->toBe(50)
        ->and($this->state->getEvidenceValue('outdated_browser'))->toHaveKey('severity_level', 'ancient_lag');
});

it('does not apply a penalty if the browser is up to date', function () {
    $log = new VisitLog([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});

it('skips processing if the browser is not recognized', function () {
    $log = new VisitLog([
        'user_agent' => 'Mozilla/5.0 (UnknownBrowser/1.0)'
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});

it('uses Client Hints over User-Agent when available', function () {
    $log = new VisitLog([
        'user_agent'     => 'Mozilla/5.0 (Chrome/90.0.0.0)', // Old version in UA
        'target_headers' => ['sec-ch-ua' => '"Google Chrome";v="119"'] // New version in CH
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    // 120 (current) - 119 (detected) = 1. No penalty (diff < 5).
    expect($this->state->getScore())->toBe(0);
});