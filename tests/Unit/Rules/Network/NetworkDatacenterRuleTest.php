<?php

use Oleant\VisitAnalytics\Rules\Network\NetworkDatacenterRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('flags as datacenter when keywords match', function () {
    $rule = new NetworkDatacenterRule();
    $state = new AnalysisState();
    $log = new VisitLog(['ip_address' => '8.8.8.8']);
    $params = [
        'datacenter_keywords' => [
            'amazon', 'aws', 'google', 'cloud', 'azure' 
        ],
        'score'    => 100,
    ];

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(100)
        ->and($state->getReasons())->toContain('datacenter_ip')
        ->and($state->getEvidenceValue('datacenter_ip')['ptr_record_match'])->toBe('dns.google');
});

it('does not flag when no keywords match', function () {
    $rule = new NetworkDatacenterRule();
    $state = new AnalysisState();
    $log = new VisitLog(['ip_address' => '1.1.1.1']);
    $params = [
        'datacenter_check' => ['keywords' => ['aws']]
    ];

    $state->addEvidence('resolved_hostname', 'home-broadband.isp.net');

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(0)
        ->and($state->getReasons())->toBeEmpty();
});