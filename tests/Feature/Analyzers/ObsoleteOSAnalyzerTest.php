<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\ObsoleteOSAnalyzer;
use Oleant\VisitAnalytics\Analyzers\Rules\ObsoleteOS\ObsoleteOSRule;
use Oleant\VisitAnalytics\Analyzers\Rules\ObsoleteOS\ObsoleteBrowserRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

beforeEach(function () {
    $this->analyzer = new ObsoleteOSAnalyzer();
    // Определяем правила, которые будем использовать в тестах
    $this->defaultRules = [ObsoleteOSRule::class, ObsoleteBrowserRule::class];
});

it('flags obsolete windows versions like XP or Vista', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1'
    ]);

    $state = new AnalysisState();
    $params = [
        'rules' => [ObsoleteOSRule::class], // Тестируем только ОС
        'target_os' => ['Windows NT 5.1', 'Windows NT 6.0'],
        'weights' => ['obsolete_os' => 75]
    ];

    $this->analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(75)
        ->and($state->getEvidenceValue('obsolete_os'))->toHaveKey('os_signature', 'Windows NT 5.1');
});

it('does not flag modern operating systems', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]);

    $state = new AnalysisState();
    $params = [
        'rules' => $this->defaultRules,
        'target_os' => ['Windows NT 5.1', 'Windows NT 6.1'],
    ];

    $this->analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0);
});

it('performs case-insensitive matching for os signatures', function () {
    $log = VisitLog::factory()->make(['user_agent' => 'MOZILLA/5.0 (WINDOWS NT 5.1)']);
    $state = new AnalysisState();
    $params = [
        'rules' => [ObsoleteOSRule::class],
        'target_os' => ['windows nt 5.1'],
    ];

    $this->analyzer->analyze($log, $state, $params);

    expect($state->getEvidenceValue('obsolete_os'))->not->toBeNull();
});

it('uses default weight when weight parameter is missing', function () {
    $log = VisitLog::factory()->make(['user_agent' => 'Windows NT 5.1']);
    $state = new AnalysisState();
    $params = [
        'rules' => [ObsoleteOSRule::class],
        'target_os' => ['Windows NT 5.1'],
        'weights' => []
    ];

    $this->analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(35);
});

it('flags obsolete browsers with default weight', function () {
    $log = VisitLog::factory()->make(['user_agent' => 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)']);
    $state = new AnalysisState();
    $params = [
        'rules' => [ObsoleteBrowserRule::class],
        'target_browsers' => ['MSIE'],
        'weights' => ['obsolete_browsers' => 35]
    ];

    $this->analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(35)
        ->and($state->getEvidenceValue('obsolete_browsers'))->toHaveKey('browsers_signature', 'MSIE');
});