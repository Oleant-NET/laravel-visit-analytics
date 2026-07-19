<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Services;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Services\BotAnalysisService;
use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\DTO\AnalysisResult;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Mockery;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

beforeEach(function () {
    VisitLog::truncate();
    
    $this->log = VisitLog::create([
        'ip_address' => '1.1.1.1',
        'user_agent' => 'Test Agent',
        'url' => 'https://test.com',
    ]);
});

/**
 * @test
 */
it('correctly orchestrates rules and returns AnalysisResult', function () {
    // Mock the RuleInterface
    $ruleMock = Mockery::mock(RuleInterface::class);
    $ruleMock->shouldReceive('apply')
        ->once()
        ->with($this->log, Mockery::type(AnalysisState::class), ['param' => 'value'])
        ->andReturnUsing(function ($log, AnalysisState $state) {
            $state->score = 50;
            $state->reasons[] = 'Suspected behavior';
        });

    app()->instance('TestRule', $ruleMock);

    config(['visit-analytics-detection' => [
        'threshold' => 70,
        'rules' => [
            'group1' => [
                'TestRule' => ['param' => 'value']
            ]
        ]
    ]]);

    $service = new BotAnalysisService();
    $result = $service->analyze($this->log);

    expect($result)->toBeInstanceOf(AnalysisResult::class)
        ->and($result->score)->toBe(50)
        ->and($result->isBot)->toBeFalse()
        ->and($result->reasons)->toContain('Suspected behavior');
});

/**
 * @test
 */
it('stops execution when the threshold is reached (early exit)', function () {
    $rule1 = Mockery::mock(RuleInterface::class);
    $rule1->shouldReceive('apply')->once()->andReturnUsing(function ($log, $state) {
        $state->score = 100;
    });

    $rule2 = Mockery::mock(RuleInterface::class);
    $rule2->shouldReceive('apply')->never();

    app()->instance('R1', $rule1);
    app()->instance('R2', $rule2);

    config(['visit-analytics-detection' => [
        'threshold' => 70,
        'rules' => [
            'g1' => ['R1' => [], 'R2' => []]
        ]
    ]]);

    (new BotAnalysisService())->analyze($this->log);
});

/**
 * @test
 */
it('captures exceptions from rules and continues', function () {
    $failingRule = Mockery::mock(RuleInterface::class);
    $failingRule->shouldReceive('apply')->once()->andThrow(new \Exception('Rule failed'));

    $workingRule = Mockery::mock(RuleInterface::class);
    $workingRule->shouldReceive('apply')->once()->andReturnUsing(function ($log, $state) {
        $state->score = 25;
    });

    app()->instance('FailingRule', $failingRule);
    app()->instance('WorkingRule', $workingRule);

    config(['visit-analytics-detection' => [
        'threshold' => 70,
        'rules' => [
            'g1' => ['FailingRule' => [], 'WorkingRule' => []]
        ]
    ]]);

    $result = (new BotAnalysisService())->analyze($this->log);

    expect($result->score)->toBe(25)
        ->and($result->evidence)->toHaveKey('execution_errors');

    $errors = $result->evidence['execution_errors'];

    $errorData = is_array($errors) && isset($errors[0]) ? $errors[0] : $errors;

    expect($errorData['rule'])->toBe('FailingRule')
        ->and($errorData['error'])->toBe('Rule failed');
});