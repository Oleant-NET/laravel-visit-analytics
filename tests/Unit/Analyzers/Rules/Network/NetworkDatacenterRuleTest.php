<?php

use Oleant\VisitAnalytics\Analyzers\Rules\Network\NetworkDatacenterRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('flags as datacenter when keywords match', function () {
    $rule = new NetworkDatacenterRule();
    $state = new AnalysisState();
    $log = new VisitLog(['ip_address' => '1.1.1.1']);
    $params = [
        'weights' => ['datacenter' => 100],
        'datacenter_check' => ['keywords' => ['hetzner', 'aws']]
    ];

    $state->addEvidence('resolved_hostname', 'static.hetzner.com');

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(100)
        ->and($state->getReasons())->toContain('datacenter_ip')
        ->and($state->getEvidenceValue('datacenter_ip')['ptr_record_match'])->toBe('static.hetzner.com');
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