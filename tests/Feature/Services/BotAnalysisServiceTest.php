<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Services;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Services\BotAnalysisService;
use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\DTO\AnalysisResult;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Mockery;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

beforeEach(function () {
    VisitLog::truncate();
    
    // Create a dummy log for analysis
    $this->log = VisitLog::create([
        'ip_address' => '1.1.1.1',
        'user_agent' => 'Test Agent',
        'url' => 'https://test.com',
    ]);
});

/**
 * @test
 * Verifies that the service correctly orchestrates a chain of analyzers.
 */
it('correctly orchestrates analyzers and returns AnalysisResult', function () {
    // 1. Mock an analyzer
    $analyzerMock = Mockery::mock(BotAnalyzerInterface::class);
    $analyzerMock->shouldReceive('analyze')
        ->once()
        ->with($this->log, Mockery::type(AnalysisState::class), ['custom' => 'param'])
        ->andReturnUsing(function ($log, AnalysisState $state) {
            $state->score += 50;
            $state->reasons[] = 'Suspected behavior';
        });

    // 2. Bind the mock to the container
    app()->instance('MockAnalyzer', $analyzerMock);

    // 3. Set up the config
    config(['visit-analytics.detection_engine' => [
        'threshold' => 70,
        'analyzers' => [
            [
                'class' => 'MockAnalyzer',
                'enabled' => true,
                'params' => ['custom' => 'param']
            ]
        ]
    ]]);

    $service = new BotAnalysisService();
    $result = $service->analyze($this->log);

    // 4. Assertions
    expect($result)->toBeInstanceOf(AnalysisResult::class)
        ->and($result->score)->toBe(50)
        ->and($result->isBot)->toBeFalse()
        ->and($result->reasons)->toContain('Suspected behavior');
});

/**
 * @test
 * Verifies that the analysis stops early once the threshold is met.
 */
it('stops execution when the threshold is reached (early exit)', function () {
    $analyzer1 = Mockery::mock(BotAnalyzerInterface::class);
    $analyzer1->shouldReceive('analyze')->once()->andReturnUsing(function ($log, $state) {
        $state->score = 100; // Trigger threshold immediately
    });

    $analyzer2 = Mockery::mock(BotAnalyzerInterface::class);
    $analyzer2->shouldReceive('analyze')->never(); // Should NOT be called

    app()->instance('A1', $analyzer1);
    app()->instance('A2', $analyzer2);

    config(['visit-analytics.detection_engine' => [
        'threshold' => 70,
        'analyzers' => [
            ['class' => 'A1', 'enabled' => true],
            ['class' => 'A2', 'enabled' => true],
        ]
    ]]);

    $service = new BotAnalysisService();
    $service->analyze($this->log);
});

/**
 * @test
 * Checks that the service captures exceptions from analyzers, 
 * logs them into evidence, and continues with the next analyzer.
 */
it('continues analysis if an analyzer throws an exception', function () {
    // 1. Mock an analyzer that fails
    $failingAnalyzer = Mockery::mock(BotAnalyzerInterface::class);
    $failingAnalyzer->shouldReceive('analyze')
        ->once()
        ->andThrow(new \Exception('Test Error'));

    // 2. Mock a working analyzer to ensure the cycle doesn't break
    $workingAnalyzer = Mockery::mock(BotAnalyzerInterface::class);
    $workingAnalyzer->shouldReceive('analyze')
        ->once()
        ->andReturnUsing(function ($log, $state) {
            $state->score = 25;
        });

    app()->instance('FailingAnalyzer', $failingAnalyzer);
    app()->instance('WorkingAnalyzer', $workingAnalyzer);

    config(['visit-analytics.detection_engine' => [
        'threshold' => 70,
        'analyzers' => [
            ['class' => 'FailingAnalyzer', 'enabled' => true],
            ['class' => 'WorkingAnalyzer', 'enabled' => true],
        ]
    ]]);

    $service = new BotAnalysisService();
    $result = $service->analyze($this->log);

    // Assertions
    expect($result->score)->toBe(25);
    expect($result->evidence)->toHaveKey('execution_errors');
    
    // Since addEvidence currently overwrites the key, execution_errors is a direct array
    $errorData = $result->evidence['execution_errors'];
    
    expect($errorData['analyzer'])->toBe('FailingAnalyzer')
        ->and($errorData['error'])->toBe('Test Error');
});

/**
 * @test
 * Verifies that disabled analyzers are ignored.
 */
it('ignores disabled analyzers', function () {
    $disabledMock = Mockery::mock(BotAnalyzerInterface::class);
    $disabledMock->shouldReceive('analyze')->never();

    app()->instance('Disabled', $disabledMock);

    config(['visit-analytics.detection_engine' => [
        'analyzers' => [
            ['class' => 'Disabled', 'enabled' => false],
        ]
    ]]);

    $service = new BotAnalysisService();
    $service->analyze($this->log);
});