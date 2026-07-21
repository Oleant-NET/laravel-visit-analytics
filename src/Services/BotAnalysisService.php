<?php

namespace Oleant\VisitAnalytics\Services;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\DTO\AnalysisResult;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Throwable;

/**
 * Class BotAnalysisService
 *
 * Orchestrates the bot detection process by executing a chain of
 * configured analyzers against a visit log entry.
 */
class BotAnalysisService
{
    /**
     * Perform a comprehensive analysis of a single visit log.
     *
     * @param VisitLog $log The raw visit log to be processed.
     * @return AnalysisResult The final result containing score, verdict, and evidence.
     */
public function analyze(VisitLog $log): AnalysisResult
    {
        $engineConfig = config('visit-analytics-detection', []);
        
        $threshold = (int)($engineConfig['threshold'] ?? 70);
        $ruleGroups = $engineConfig['rules'] ?? [];

        $state = new AnalysisState();

        foreach ($ruleGroups as $group => $rules) {
            foreach ($rules as $class => $params) {
                try {
                    /** @var \Oleant\VisitAnalytics\Contracts\RuleInterface $rule */
                    $rule = app($class);
                    
                    $rule->apply($log, $state, $params);

                } catch (Throwable $e) {
                    report($e);
                    $state->addEvidence('execution_errors', [
                        'group' => $group,
                        'rule'  => $class,
                        'error' => $e->getMessage(),
                    ]);
                    continue;
                }

                // Early Exit
                if ($state->score >= $threshold) {
                    break 2;
                }
            }
        }

        return new AnalysisResult(
            score: (int)min($state->score, 100),
            isBot: $state->score >= $threshold,
            reasons: array_values(array_unique($state->reasons)),
            evidence: $state->evidence,
            isOfficialBot: $state->isOfficialBot,
            newLookups: $state->newLookups
        );
    }
}