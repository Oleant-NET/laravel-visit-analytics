<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\OutdatedBrowserAnalyzer;
use Oleant\VisitAnalytics\Analyzers\Rules\OutdatedBrowser\OutdatedBrowserRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * Helper to get default params with the necessary rule registered
 */
function getParams(array $custom = []): array
{
    return array_merge([
        'enabled' => true,
        'rules'   => [OutdatedBrowserRule::class], // Обязательное добавление правила
    ], $custom);
}

it('skips analysis when disabled', function () {
    $log = VisitLog::factory()->make(['user_agent' => 'Chrome/100.0.0.0']);
    $state = new AnalysisState();
    $analyzer = new OutdatedBrowserAnalyzer();

    $analyzer->analyze($log, $state, ['enabled' => false]);

    expect($state->getScore())->toBe(0);
});

it('detects outdated versions via client hints', function () {
    $log = VisitLog::factory()->make([
        'target_headers' => [
            'sec-ch-ua' => '"Not A;Brand";v="99", "Chromium";v="120", "Google Chrome";v="110"'
        ]
    ]);

    $state = new AnalysisState();
    $analyzer = new OutdatedBrowserAnalyzer();
    
    $params = getParams([
        'current_versions' => ['chrome' => 125],
        'scoring' => [
            'minor_lag' => ['diff' => 5, 'score' => 20],
            'major_lag' => ['diff' => 10, 'score' => 50],
        ]
    ]);

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(50)
        ->and($state->getReasons())->toContain('outdated_browser')
        ->and($state->getEvidenceValue('outdated_browser'))->toMatchArray([
            'browser'        => 'chrome',
            'user_version'   => 110,
            'version_lag'    => 15,
            'severity_level' => 'major_lag',
            'target_version' => 125
        ]);
});

it('falls back to user agent when client hints are missing', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 ... Chrome/90.0.4430.212 Safari/537.36',
        'target_headers' => []
    ]);

    $state = new AnalysisState();
    $analyzer = new OutdatedBrowserAnalyzer();
    
    $params = getParams([
        'current_versions' => ['chrome' => 120],
        'scoring' => [
            'ancient_lag' => ['diff' => 20, 'score' => 80],
        ]
    ]);

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(80)
        ->and($state->getEvidenceValue('outdated_browser'))->toHaveKey('user_version', 90);
});

it('does not penalize modern or future browser versions', function () {
    $log = VisitLog::factory()->make(['user_agent' => 'Chrome/130.0.0.0']);
    $state = new AnalysisState();
    $analyzer = new OutdatedBrowserAnalyzer();
    
    $params = getParams([
        'current_versions' => ['chrome' => 125],
        'scoring' => ['minor_lag' => ['diff' => 1, 'score' => 10]]
    ]);

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0);
});

it('applies the highest applicable penalty level', function () {
    $log = VisitLog::factory()->make(['user_agent' => 'Chrome/50.0.0.0']);
    $state = new AnalysisState();
    $analyzer = new OutdatedBrowserAnalyzer();
    
    $params = getParams([
        'current_versions' => ['chrome' => 120],
        'scoring' => [
            'level_1' => ['diff' => 10, 'score' => 10],
            'level_2' => ['diff' => 30, 'score' => 30],
            'level_3' => ['diff' => 50, 'score' => 50],
        ]
    ]);

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(50)
        ->and($state->getEvidenceValue('outdated_browser'))->toHaveKey('severity_level', 'level_3');
});