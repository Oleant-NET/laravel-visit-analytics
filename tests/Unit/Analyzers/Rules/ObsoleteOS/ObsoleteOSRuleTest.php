<?php

use Oleant\VisitAnalytics\Analyzers\Rules\ObsoleteOS\ObsoleteOSRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('adds a penalty when an obsolete OS signature is found', function () {
    $rule = new ObsoleteOSRule();
    $state = new AnalysisState();
    $log = new VisitLog(['user_agent' => 'Mozilla/5.0 (Windows NT 5.1; rv:10.0)']);
    
    $params = [
        'target_os' => ['Windows NT 5.1'],
        'weights' => ['obsolete_os' => 40]
    ];

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(40)
        ->and($state->getEvidenceValue('obsolete_os'))->toHaveKey('os_signature', 'Windows NT 5.1');
});

it('does not add a penalty if the OS is not obsolete', function () {
    $rule = new ObsoleteOSRule();
    $state = new AnalysisState();
    $log = new VisitLog(['user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)']);
    
    $params = [
        'target_os' => ['Windows NT 5.1']
    ];

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(0);
});