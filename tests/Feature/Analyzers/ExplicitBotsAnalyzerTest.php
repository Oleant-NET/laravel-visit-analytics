<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\ExplicitBotsAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * @test
 * Verifies that the analyzer correctly identifies a bot from the 
 * User-Agent string using the provided signatures.
 */
it('identifies bots based on user agent signatures', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    ]);

    $state = new AnalysisState();
    $analyzer = new ExplicitBotsAnalyzer();
    
    $params = [
        'rules' => [\Oleant\VisitAnalytics\Analyzers\Rules\ExplicitBots\ExplicitBotsRule::class],
        'explicit_bots' => ['googlebot', 'bingbot'],
        'weights' => ['ua_explicit' => 100]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(100)
        ->and($state->getReasons())->toContain('explicit_bot')
        ->and($state->isOfficialBot)->toBeTrue()
        ->and($state->getEvidence())->toHaveKey('explicit_bot.bot_signature', 'googlebot');
});

/**
 * @test
 * Confirms that the check is case-insensitive.
 */
it('is case insensitive when matching signatures', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'CRAWLER-X/1.0'
    ]);

    $state = new AnalysisState();
    $analyzer = new ExplicitBotsAnalyzer();
    
    $params = [
        'rules' => [\Oleant\VisitAnalytics\Analyzers\Rules\ExplicitBots\ExplicitBotsRule::class],
        'explicit_bots' => ['crawler-x'],
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->isOfficialBot)->toBeTrue();
});

/**
 * @test
 * Ensures that a legitimate user agent does not trigger the bot flag.
 */
it('does not flag legitimate user agents', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]);

    $state = new AnalysisState();
    $analyzer = new ExplicitBotsAnalyzer();
    
    $params = [
        'explicit_bots' => ['googlebot', 'slurp'],
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0)
        ->and($state->isOfficialBot)->toBeFalse();
});

/**
 * @test
 * Verifies that empty signatures or missing User-Agents are handled gracefully.
 */
it('skips analysis on empty user agent or empty signatures list', function () {
    $analyzer = new ExplicitBotsAnalyzer();

    // Scenario 1: Empty UA
    $logNoUa = VisitLog::factory()->make(['user_agent' => '']);
    $state1 = new AnalysisState();
    $analyzer->analyze($logNoUa, $state1, ['explicit_bots' => ['bot']]);
    expect($state1->getScore())->toBe(0);

    // Scenario 2: Empty Signatures in config
    $logWithUa = VisitLog::factory()->make(['user_agent' => 'SomeBot']);
    $state2 = new AnalysisState();
    $analyzer->analyze($logWithUa, $state2, ['explicit_bots' => []]);
    expect($state2->getScore())->toBe(0);
});