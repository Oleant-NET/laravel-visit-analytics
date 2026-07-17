<?php

use Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderWeightsRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('penalizes missing mandatory headers based on weights', function () {
    $rule = new HeaderWeightsRule();
    $state = new AnalysisState();
    
    // Log with no headers
    $log = new VisitLog(['target_headers' => [], 'user_agent' => 'Mozilla/5.0']);
    
    $rule->apply($log, $state, [
        'weights' => ['Accept' => 25]
    ]);

    expect($state->getScore())->toBe(25)
        ->and($state->getReasons())->toContain('missing_mandatory_header_accept');
});