<?php

/**
 * Feature test for the BotnetReputationAnalyzer.
 * * This suite verifies the integration between the reputation analyzer and the 
 * BotnetService. It ensures that suspicious clusters are correctly identified,
 * penalized, and that official bots or ignored patterns are excluded from analysis.
 */

use Oleant\VisitAnalytics\Analyzers\BotnetReputationAnalyzer;
use Oleant\VisitAnalytics\Services\BotnetService;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Tests\TestCase;
use Mockery\MockInterface;

uses(TestCase::class);

/**
 * @test
 * Verifies that the analyzer records evidence when the BotnetService 
 * confirms a match for a known botnet fingerprint.
 */
it('adds penalty points if UA is a known botnet', function () {
    $ua = 'Known-Botnet-UA';
    $log = new VisitLog(['user_agent' => $ua]);
    $state = new AnalysisState();
    
    // Configuration parameters with specific weight for botnet detection
    $params = [
        'weights' => [
            'known_botnet' => 100
        ],
        'ignore_patterns' => []
    ];

    /** @var BotnetService|MockInterface $service */
    $service = mock(BotnetService::class, function (MockInterface $mock) use ($ua) {
        $mock->shouldReceive('isKnownBotnet')
            ->once()
            ->with($ua)
            ->andReturn(true);
    });

    $analyzer = new BotnetReputationAnalyzer($service);
    $analyzer->analyze($log, $state, $params);

    /**
     * Assert that the evidence was recorded correctly.
     * Based on AnalysisState::addEvidence(string $key, mixed $value)
     */
    expect($state->evidence)->toHaveKey('known_botnet', 100);
});

/**
 * @test
 * Confirms that the analyzer skips processing for visitors already identified 
 * as official bots (e.g., Google, Bing) to optimize database performance.
 */
it('skips analysis if visitor is an official bot', function () {
    $state = new AnalysisState();
    $state->isOfficialBot = true; 
    
    /** @var BotnetService|MockInterface $service */
    $service = mock(BotnetService::class);
    
    // The service must NOT be called if the visitor is already flagged as official
    $service->shouldNotReceive('isKnownBotnet');

    $analyzer = new BotnetReputationAnalyzer($service);
    $analyzer->analyze(new VisitLog(['user_agent' => 'Googlebot']), $state);
    
    // Ensure no evidence was added
    expect($state->evidence)->toBeEmpty();
});

/**
 * @test
 * Ensures that the analyzer respects the 'ignore_patterns' configuration
 * and halts analysis before hitting the fingerprint database.
 */
it('respects ignore patterns and skips analysis', function () {
    $ua = 'Internal-Monitoring-Agent/2.0';
    $log = new VisitLog(['user_agent' => $ua]);
    $state = new AnalysisState();
    
    $params = [
        'ignore_patterns' => ['Internal-Monitoring']
    ];

    /** @var BotnetService|MockInterface $service */
    $service = mock(BotnetService::class);
    $service->shouldNotReceive('isKnownBotnet');

    $analyzer = new BotnetReputationAnalyzer($service);
    $analyzer->analyze($log, $state, $params);

    expect($state->evidence)->toBeEmpty();
});