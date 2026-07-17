<?php

use Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderCookieRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('adds evidence when cookie header is tracked and missing', function () {
    $rule = new HeaderCookieRule();
    $state = new AnalysisState();
    
    $log = new VisitLog(['target_headers' => []]);
    
    $rule->apply($log, $state, [
        'target_headers' => ['cookie'] // enabled tracking
    ]);

    expect($state->getEvidence())->toHaveKey('cookie_missing_in_headers', true);
});

it('does not add evidence when cookie is present', function () {
    $rule = new HeaderCookieRule();
    $state = new AnalysisState();
    
    $log = new VisitLog(['target_headers' => ['cookie' => 'session=123']]);
    
    $rule->apply($log, $state, [
        'target_headers' => ['cookie']
    ]);

    expect($state->getEvidence())->not->toHaveKey('cookie_missing_in_headers');
});