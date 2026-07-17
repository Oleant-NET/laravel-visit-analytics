<?php

namespace Oleant\VisitAnalytics\Analyzers\Base;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;
use InvalidArgumentException;

/**
 * Class AbstractAnalyzer
 * 
 * Serves as a base class for all analyzers that rely on a chain of rules.
 * It provides a unified execution engine to process rules against the analysis state.
 */
abstract class AbstractAnalyzer
{
    /**
     * Iterates through the provided list of rule classes and applies them
     * until the score threshold is met or all rules are executed.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params Expected keys: 'rules' (array of class strings), 'threshold' (int)
     * @return void
     * 
     * @throws InvalidArgumentException if a rule does not implement RuleInterface
     */
    protected function executeRules(VisitLog $log, AnalysisState $state, array $params): void
    {
        $rules = $params['rules'] ?? [];
        $threshold = $params['threshold'] ?? 70;

        foreach ($rules as $ruleClass) {
            // Stop execution if the threshold is reached
            if ($state->getScore() >= $threshold) {
                break;
            }

            $rule = app($ruleClass);

            // Validate the rule contract
            if (!$rule instanceof RuleInterface) {
                throw new InvalidArgumentException(
                    "Class {$ruleClass} must implement RuleInterface."
                );
            }

            $rule->apply($log, $state, $params);
        }
    }
}