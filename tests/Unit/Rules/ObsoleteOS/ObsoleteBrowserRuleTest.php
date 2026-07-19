<?php

use Oleant\VisitAnalytics\Rules\ObsoleteOS\ObsoleteBrowserRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('adds a penalty when an obsolete browser signature is found', function () {
    $rule = new ObsoleteBrowserRule();
    $state = new AnalysisState();
    $log = new VisitLog(['user_agent' => 'Mozilla/5.0 (MSIE 6.0; Windows NT 5.1)']);
    
    $params = [
        'target_browsers' => [
            'MSIE', 'Trident/', 'Opera/8', 'Opera/9',
        ],
        'score' => 35,
    ];

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(35)
        ->and($state->getEvidenceValue('obsolete_browsers'))->toHaveKey('browsers_signature', 'MSIE');
});

it('does not add a penalty if the browser is modern', function () {
    $rule = new ObsoleteBrowserRule();
    $state = new AnalysisState();
    $log = new VisitLog(['user_agent' => 'Mozilla/5.0 (Chrome/120.0.0.0)']);
    
    $params = [
        'target_browsers' => ['MSIE 6.0']
    ];

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(0);
});