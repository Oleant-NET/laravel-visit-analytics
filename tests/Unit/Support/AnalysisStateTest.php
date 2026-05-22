<?php

namespace Oleant\VisitAnalytics\Tests\Unit\Support;

use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

it('accumulates scores correctly', function () {
    $state = new AnalysisState();
    $state->add(20, 'reason_1');
    $state->add(30, 'reason_2');

    expect($state->getScore())->toBe(50)
        ->and($state->getReasons())->toHaveCount(2);
});

it('merges evidence data', function () {
    $state = new AnalysisState();
    
    $state->add(10, 'reason', ['key1' => 'val1']);

    $state->addEvidence('key2', 'val2');

    $evidence = $state->getEvidence();

    expect($evidence)->toHaveKey('reason.key1', 'val1')
        ->and($evidence)->toHaveKey('key2', 'val2');
});

it('tracks official bot status', function () {
    $state = new AnalysisState();
    
    expect($state->isOfficialBot)->toBeFalse();
    
    $state->isOfficialBot = true;
    expect($state->isOfficialBot)->toBeTrue();
});