<?php

use Oleant\VisitAnalytics\Rules\ObsoleteOS\ObsoleteOSRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('adds a penalty when an obsolete OS signature is found', function () {
    $rule = new ObsoleteOSRule();
    $state = new AnalysisState();
    $log = new VisitLog(['user_agent' => 'Mozilla/5.0 (Windows NT 6.1; rv:10.0)']);
    
    $params = [
        'target_os' => [
            'Windows 95', 'Win95', 'Windows 98', 'Win98', 'Windows ME', 'Windows NT 5.', 'Windows NT 6.0',  'Windows NT 6.1',  'Windows NT 6.2',  'Windows NT 6.3', 'Mac OS X 10', 'Android 4.', 'Android 5.', 'Android 6.',
        ],
        'score' => 35,
    ];

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(35)
        ->and($state->getEvidenceValue('obsolete_os'))->toHaveKey('os_signature', 'Windows NT 6.1');
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