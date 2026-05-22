<?php

namespace Oleant\VisitAnalytics\Tests\Unit\Support;

use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * @test
 * Verifies the default initial state of the AnalysisState object.
 */
it('initializes with default values', function () {
    $state = new AnalysisState();

    expect($state->getScore())->toBe(0)
        ->and($state->getReasons())->toBeEmpty()
        ->and($state->getEvidence())->toBeEmpty()
        ->and($state->isOfficialBot)->toBeFalse()
        ->and($state->newLookups)->toBe(0);
});

/**
 * @test
 * Checks if the add() method correctly increments the score 
 * and accumulates reasons and evidence.
 */
it('correctly adds points and reasons', function () {
    $state = new AnalysisState();

    $state->add(20, 'suspicious_header', ['header_key' => 'X-Bot-Header']);
    $state->add(30, 'datacenter_ip', ['isp' => 'DigitalOcean']);

    expect($state->getScore())->toBe(50)
        ->and($state->getReasons())->toEqual(['suspicious_header', 'datacenter_ip'])
        ->and($state->getEvidence())->toMatchArray([
            'suspicious_header' => [
                'header_key' => 'X-Bot-Header'
            ],
            'datacenter_ip' => [
                'isp' => 'DigitalOcean'
            ]
        ]);
});

/**
 * @test
 * Verifies that addEvidence() adds metadata without changing the score or reasons.
 */
it('can add evidence without affecting the score', function () {
    $state = new AnalysisState();

    $state->addEvidence('ptr_record', 'crawl-1-2-3-4.googlebot.com');

    expect($state->getScore())->toBe(0)
        ->and($state->getReasons())->toBeEmpty()
        ->and($state->getEvidence())->toHaveKey('ptr_record', 'crawl-1-2-3-4.googlebot.com');
});

/**
 * @test
 * Ensures that merging evidence data works correctly when adding multiple times.
 */
it('merges evidence data when multiple calls are made', function () {
    $state = new AnalysisState();

    $state->add(10, 'reason_1', ['key1' => 'val1']);
    $state->add(10, 'reason_2', ['key2' => 'val2']);

    $evidence = $state->getEvidence();

    expect($evidence)->toHaveCount(2)
        ->and($evidence)->toHaveKey('reason_1.key1', 'val1')
        ->and($evidence)->toHaveKey('reason_2.key2', 'val2');
});

/**
 * @test
 * Verifies that the state correctly tracks the official bot status and lookup counts.
 */
it('tracks public flags and counters', function () {
    $state = new AnalysisState();
    
    $state->isOfficialBot = true;
    $state->newLookups = 5;

    expect($state->isOfficialBot)->toBeTrue()
        ->and($state->newLookups)->toBe(5);
});