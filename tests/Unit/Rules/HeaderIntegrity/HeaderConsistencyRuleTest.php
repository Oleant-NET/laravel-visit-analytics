<?php

use Oleant\VisitAnalytics\Rules\HeaderIntegrity\HeaderConsistencyRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('flags platform mismatch between UA and client hints', function () {
    $rule = new HeaderConsistencyRule();
    $state = new AnalysisState();
    
    $log = new VisitLog([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0)',
        'target_headers' => ['sec-ch-ua-platform' => 'macOS']
    ]);
    
    $rule->apply($log, $state, [
        'os_platform_mismatch_score' => 50,
    ]);

    expect($state->getScore())->toBe(50)
        ->and($state->getReasons())->toContain('fingerprint_mismatch');
});

it('flags architecture conflict', function () {
    $rule = new HeaderConsistencyRule();
    $state = new AnalysisState();
    
    $log = new VisitLog([
        'user_agent' => 'Mozilla/5.0 (Intel Mac OS X)',
        'target_headers' => [
            'sec-ch-ua-arch' => 'arm',
            'cookie' => 'session=123'
        ]
    ]);
    
    $rule->apply($log, $state, [
        'high_entropy' => [
            'headers' => [
                'sec-ch-ua-platform-version',
                'sec-ch-ua-full-version-list',
                'sec-ch-ua-model',
            ],
            'score'   => 20,
        ],
        'arch_architecture_mismatch_score' => 25,
    ]);

    expect($state->getScore())->toBe(25);
});

it('hight entropy header', function () {
    $rule = new HeaderConsistencyRule();
    $state = new AnalysisState();
    
    $log = new VisitLog([
        'user_agent' => 'Mozilla/5.0 (Intel Mac OS X)',
        'target_headers' => [
            'sec-ch-ua-platform-version' => 'arm86/265',
        ]
    ]);
    
    $rule->apply($log, $state, [
        'high_entropy' => [
            'headers' => [
                'sec-ch-ua-platform-version',
                'sec-ch-ua-full-version-list',
                'sec-ch-ua-model',
            ],
            'score'   => 20,
        ],
    ]);

    expect($state->getScore())->toBe(20);
});