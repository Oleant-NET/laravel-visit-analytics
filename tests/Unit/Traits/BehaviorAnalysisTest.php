<?php

use Oleant\VisitAnalytics\Traits\BehaviorAnalysis;
use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Support\Carbon;

class BehaviorAnalysisMock
{
    use BehaviorAnalysis {
        header as public;
        isAjaxRequest as public;
        ensureCarbon as public;
    }
}

it('detects ajax requests', function () {
    $mock = new BehaviorAnalysisMock();
    
    $log = new VisitLog(['target_headers' => ['x-requested-with' => 'XMLHttpRequest']]);
    expect($mock->isAjaxRequest($log))->toBeTrue();

    $logOther = new VisitLog(['target_headers' => ['x-requested-with' => 'fetch']]);
    expect($mock->isAjaxRequest($logOther))->toBeFalse();
});

it('safely retrieves headers', function () {
    $mock = new BehaviorAnalysisMock();
    $log = new VisitLog(['target_headers' => ['user-agent' => 'Mozilla/5.0']]);

    expect($mock->header($log, 'user-agent'))->toBe('Mozilla/5.0')
        ->and($mock->header($log, 'non-existent'))->toBeNull();

    // Verify behavior with corrupted or non-array header data
    $logBad = new VisitLog(['target_headers' => 'not-an-array']);
    expect($mock->header($logBad, 'user-agent'))->toBeNull();
});

it('ensures carbon instance', function () {
    $mock = new BehaviorAnalysisMock();
    $date = '2026-07-18 19:37:00';
    $carbon = Carbon::parse($date);

    // Test with string input
    $result1 = $mock->ensureCarbon($date);
    expect($result1)->toBeInstanceOf(Carbon::class)
        ->and($result1->toDateTimeString())->toBe($date);

    // Test with existing Carbon instance
    $result2 = $mock->ensureCarbon($carbon);
    expect($result2)->toBeInstanceOf(Carbon::class)
        ->and($result2)->toBe($carbon);
});