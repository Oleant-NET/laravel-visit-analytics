<?php

use Oleant\VisitAnalytics\Rules\HeaderIntegrity\HeaderDiversityRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('flags when header count is below threshold', function () {
    $rule = new HeaderDiversityRule();
    $state = new AnalysisState();
    
    // Log with only 2 headers
    $log = new VisitLog(['target_headers' => ['Host' => 'a.com', 'Accept' => '*/*']]);
    
    $rule->apply($log, $state, [
        'min_total_headers' => ['count' => 5, 'score' => 40]
    ]);

    expect($state->getScore())->toBe(40)
        ->and($state->getReasons())->toContain('suspicious_minimal_headers');
});