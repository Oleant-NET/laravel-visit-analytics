<?php

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Analyzers\Rules\Referer\PortLeakRule;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);
uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

it('adds penalty when referer contains a known server port', function () {
    $rule = new PortLeakRule();
    $state = new AnalysisState();
    $log = VisitLog::factory()->create(['referer' => 'http://example.com:2082/']);
    
    // Apply rule with specific weight
    $rule->apply($log, $state, ['weights' => ['port_leak' => 50]]);

    expect($state->getScore())->toBe(50)
        ->and($state->getReasons())->toContain('port_leak');
});

it('does not penalize standard URLs', function () {
    $rule = new PortLeakRule();
    $state = new AnalysisState();
    $log = VisitLog::factory()->create(['referer' => 'https://google.com']);
    
    $rule->apply($log, $state, ['weights' => ['port_leak' => 50]]);

    expect($state->getScore())->toBe(0);
});