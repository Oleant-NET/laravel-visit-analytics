<?php

use Oleant\VisitAnalytics\Analyzers\Rules\ExplicitBots\ExplicitBotsRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

it('identifies an explicit bot when signature matches', function () {
    // Arrange: создаем "легкий" объект (не нужно сохранять в БД)
    $log = new VisitLog(['user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1)']);
    $state = new AnalysisState();
    $rule = new ExplicitBotsRule();
    
    $params = [
        'explicit_bots' => ['Googlebot', 'Bingbot'],
        'weights' => ['ua_explicit' => 100]
    ];

    // Act
    $rule->apply($log, $state, $params);

    // Assert
    expect($state->getScore())->toBe(100)
        ->and($state->isOfficialBot)->toBeTrue();
});

it('ignores request when UA is empty', function () {
    $log = new VisitLog(['user_agent' => '']);
    $state = new AnalysisState();
    $rule = new ExplicitBotsRule();

    $rule->apply($log, $state, []);

    expect($state->getScore())->toBe(0);
});

it('does not add points if no signature matches', function () {
    $log = new VisitLog(['user_agent' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)']);
    $state = new AnalysisState();
    $rule = new ExplicitBotsRule();
    
    $params = ['explicit_bots' => ['Googlebot']];

    $rule->apply($log, $state, $params);

    expect($state->getScore())->toBe(0)
        ->and($state->isOfficialBot)->toBeFalse();
});