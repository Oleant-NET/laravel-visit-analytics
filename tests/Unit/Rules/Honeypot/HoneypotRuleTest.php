<?php

use Oleant\VisitAnalytics\Rules\Honeypot\HoneypotRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('flags visits to defined honeypot paths', function () {
    $rule = new HoneypotRule();
    $state = new AnalysisState();
    
    // Log simulating a hit on a honeypot
    $log = new VisitLog(['url' => 'https://example.com/.env']);
    
    $rule->apply($log, $state, [
        'honeypot_paths' => ['.env', '/admin'],
        'weights' => ['honeypot' => 100]
    ]);

    expect($state->getScore())->toBe(100)
        ->and($state->getReasons())->toContain('honeypot_trap')
        ->and($state->getEvidence())->toHaveKey('honeypot_trap.matched_trap', '.env');
});

it('does not flag legitimate paths', function () {
    $rule = new HoneypotRule();
    $state = new AnalysisState();
    
    // Log simulating a normal page hit
    $log = new VisitLog(['url' => 'https://example.com/about-us']);
    
    $rule->apply($log, $state, [
        'honeypot_paths' => ['.env', '/admin'],
    ]);

    expect($state->getScore())->toBe(0)
        ->and($state->getReasons())->not->toContain('honeypot_trap');
});

it('uses default score when weights are missing', function () {
    $rule = new HoneypotRule();
    $state = new AnalysisState();
    
    $log = new VisitLog(['url' => 'https://example.com/config.php']);
    
    $rule->apply($log, $state, [
        'honeypot_paths' => ['config.php']
        // 'weights' is omitted to test default behavior
    ]);

    expect($state->getScore())->toBe(100); // Default value
});