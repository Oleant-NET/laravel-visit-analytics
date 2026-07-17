<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\NetworkAnalyzer;
use Oleant\VisitAnalytics\Analyzers\Rules\Network\NetworkDatacenterRule;
use Oleant\VisitAnalytics\Analyzers\Rules\Network\NetworkPtrRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Traits\ResolvesHostname;
use ReflectionClass;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * Helper to clear the static cache of the ResolvesHostname trait.
 * We use reflection to reset the static property between tests.
 */
function clearNetworkCache() {
    $reflection = new ReflectionClass(ResolvesHostname::class);
    $property = $reflection->getProperty('dnsCache');
    $property->setAccessible(true);
    $property->setValue(null, []);
}

beforeEach(function () {
    clearNetworkCache();
    
    // Define the default rule set for integration tests
    $this->defaultRules = [
        NetworkPtrRule::class,
        NetworkDatacenterRule::class
    ];
});

/**
 * @test
 * Ensures the analyzer correctly identifies datacenter IPs based on hostname keywords.
 */
it('flags datacenter IPs based on host keywords', function () {
    $log = VisitLog::factory()->make(['ip_address' => '8.8.8.8']);
    $state = new AnalysisState();
    $analyzer = new NetworkAnalyzer();
    
    $params = [
        'rules' => $this->defaultRules,
        'datacenter_check' => ['keywords' => ['google']],
        'weights' => ['datacenter' => 100]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('datacenter_ip')
        ->and($state->getScore())->toBe(100);
});

/**
 * @test
 * Verifies that IPv4 addresses lacking a PTR record are penalized.
 */
it('penalizes IPv4 with no reverse DNS record', function () {
    $log = VisitLog::factory()->make(['ip_address' => '0.0.0.0']);
    $state = new AnalysisState();
    $analyzer = new NetworkAnalyzer();
    
    $params = [
        'rules' => $this->defaultRules,
        'weights' => ['no_dns_record' => 50]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('no_ptr_record')
        ->and($state->getScore())->toBe(50);
});

/**
 * @test
 * Confirms that missing PTR records for IPv6 are ignored, as many residential 
 * ISPs do not provide them by default.
 */
it('ignores missing PTR records for IPv6 addresses', function () {
    $log = VisitLog::factory()->make(['ip_address' => '2a02:590:703:ed00::0']);
    $state = new AnalysisState();
    $analyzer = new NetworkAnalyzer();
    
    $params = [
        'rules' => $this->defaultRules,
        'weights' => ['no_dns_record' => 50]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0);
});

/**
 * @test
 * Checks that the analyzer utilizes the static cache for repeated lookups of the same IP,
 * preventing redundant DNS queries.
 */
it('uses static cache for repeated lookups', function () {
    $log = VisitLog::factory()->make(['ip_address' => '1.1.1.1']);
    $analyzer = new NetworkAnalyzer();
    $params = ['rules' => $this->defaultRules];

    // First analysis
    $state1 = new AnalysisState();
    $analyzer->analyze($log, $state1, $params);

    // Second analysis
    $state2 = new AnalysisState();
    $analyzer->analyze($log, $state2, $params);

    expect($state2->getScore())->toBe($state1->getScore());
});

/**
 * @test
 * Validates that valid PTR records without datacenter keywords do not trigger a penalty.
 */
it('does not flag IPs with valid PTR records that lack DC keywords', function () {
    $log = VisitLog::factory()->make(['ip_address' => '8.8.4.4']);
    $state = new AnalysisState();
    $analyzer = new NetworkAnalyzer();
    
    $params = [
        'rules' => $this->defaultRules,
        'datacenter_check' => ['keywords' => ['non-existent-keyword-xyz']],
        'weights' => ['datacenter' => 100]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0);
});

/**
 * @test
 * Ensures the analysis is safely skipped if the log has no IP address.
 */
it('skips analysis if ip_address is missing', function () {
    $log = VisitLog::factory()->make(['ip_address' => null]);
    $state = new AnalysisState();
    $analyzer = new NetworkAnalyzer();

    $analyzer->analyze($log, $state, ['rules' => $this->defaultRules]);

    // Score should be 0 and no evidence should be collected
    expect($state->getScore())->toBe(0)
        ->and($state->getEvidence())->toBeEmpty();
});