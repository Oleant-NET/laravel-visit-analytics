<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\ObsoleteOSAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * @test
 * Verifies that the analyzer flags User-Agents containing 
 * obsolete Windows versions (e.g., Windows XP).
 */
it('flags obsolete windows versions like XP or Vista', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1'
    ]);

    $state = new AnalysisState();
    $analyzer = new ObsoleteOSAnalyzer();
    
    $params = [
        'target_os' => ['Windows NT 5.1', 'Windows NT 6.0'],
        'weights' => ['obsolete_os' => 75]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(75)
        ->and($state->getReasons())->toContain('obsolete_os')
        ->and($state->getEvidence())->toHaveKey('os_signature', 'Windows NT 5.1');
});

/**
 * @test
 * Ensures that modern Operating Systems do not trigger any flags.
 */
it('does not flag modern operating systems', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]);

    $state = new AnalysisState();
    $analyzer = new ObsoleteOSAnalyzer();
    
    $params = [
        'target_os' => ['Windows NT 5.1', 'Windows NT 6.1'],
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0)
        ->and($state->getReasons())->toBeEmpty();
});

/**
 * @test
 * Confirms that the search for OS signatures is case-insensitive.
 */
it('performs case-insensitive matching for os signatures', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'MOZILLA/5.0 (WINDOWS NT 5.1)'
    ]);

    $state = new AnalysisState();
    $analyzer = new ObsoleteOSAnalyzer();
    
    $params = [
        'target_os' => ['windows nt 5.1'],
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('obsolete_os');
});

/**
 * @test
 * Validates that only one penalty is applied even if multiple 
 * obsolete patterns are found in the User-Agent.
 */
it('stops scoring after the first matched pattern', function () {
    $log = VisitLog::factory()->make([
        // UA containing multiple potential markers
        'user_agent' => 'Windows NT 5.1; Windows NT 6.0;'
    ]);

    $state = new AnalysisState();
    $analyzer = new ObsoleteOSAnalyzer();
    
    $params = [
        'target_os' => ['Windows NT 5.1', 'Windows NT 6.0'],
        'weights' => ['obsolete_os' => 60]
    ];

    $analyzer->analyze($log, $state, $params);

    // Score should be 60, not 120
    expect($state->getScore())->toBe(60)
        ->and($state->getReasons())->toHaveCount(1);
});

/**
 * @test
 * Ensures the analyzer uses the default weight if no specific 
 * weight is provided in the configuration.
 */
it('uses default weight when weight parameter is missing', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Windows NT 5.1'
    ]);

    $state = new AnalysisState();
    $analyzer = new ObsoleteOSAnalyzer();
    
    $params = [
        'target_os' => ['Windows NT 5.1'],
        'weights' => [] // Weight is missing
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(35);
});

/**
 * @test
 * Ensures the analyzer flags obsolete browsers and uses default weight 
 * if no specific weight is provided for browsers.
 */
it('flags obsolete browsers with default weight', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)'
    ]);

    $state = new AnalysisState();
    $analyzer = new ObsoleteOSAnalyzer();
    
    $params = [
        'target_os' => ['Windows NT 5.1'], // ОС должна быть в списке, чтобы открыть путь второму циклу
        'target_browsers' => ['MSIE'],
        'weights' => [
            'obsolete_os' => 0 // Обнуляем вес ОС, чтобы проверить именно 35 баллов от браузера
        ]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(35)
        ->and($state->getReasons())->toContain('obsolete_browsers')
        ->and($state->getEvidence())->toHaveKey('browsers_signature', 'MSIE');
});