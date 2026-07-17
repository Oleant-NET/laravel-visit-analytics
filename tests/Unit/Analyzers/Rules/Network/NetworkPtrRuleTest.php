<?php

use Oleant\VisitAnalytics\Analyzers\Rules\Network\NetworkPtrRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('adds penalty when PTR record is missing for IPv4', function () {
    $rule = new NetworkPtrRule();
    $state = new AnalysisState();
    $log = new VisitLog(['ip_address' => '1.2.3.4']);
    $params = ['weights' => ['no_dns_record' => 50]];

    // Simulate no hostname found
    $state->addEvidence('resolved_hostname', null);

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(50)
        ->and($state->getReasons())->toContain('no_ptr_record');
});

it('ignores missing PTR record for IPv6', function () {
    $rule = new NetworkPtrRule();
    $state = new AnalysisState();
    // IPv6 address
    $log = new VisitLog(['ip_address' => '2001:0db8:85a3:0000:0000:8a2e:0370:7334']);
    $params = ['weights' => ['no_dns_record' => 50]];

    $state->addEvidence('resolved_hostname', null);

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(0)
        ->and($state->getReasons())->toBeEmpty();
});