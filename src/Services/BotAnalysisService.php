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
        $engineConfig = config('visit-analytics.detection_engine', []);
        
        /** @var int $threshold The score at which a visitor is classified as a bot */
        $threshold = (int)($engineConfig['threshold'] ?? 70);
        
        /** @var array $analyzers List of enabled analyzer configurations */
        $analyzers = $engineConfig['analyzers'] ?? [];

        $state = new AnalysisState();

        foreach ($analyzers as $settings) {
            if (!($settings['enabled'] ?? false)) {
                continue;
            }

            try {
                /** @var \Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface $analyzer */
                $analyzer = app($settings['class']);
                
                // Pass only the 'params' sub-array to ensure encapsulation
                $analyzer->analyze($log, $state, array_merge((array)($settings['params'] ?? []), [
                    'threshold' => $threshold,
		    'rules' => $settings['rules'],
                ]));

            } catch (Throwable $e) {
                // Report the error to the logs/Sentry without breaking the loop
                report($e);

                $state->addEvidence('execution_errors', [
                    'analyzer' => $settings['class'],
                    'error'    => $e->getMessage(),
                ]);
                
                continue;
            }

            // Early Exit: Stop execution if the threshold is already met or exceeded
            if ($state->score >= $threshold) {
                break;
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
