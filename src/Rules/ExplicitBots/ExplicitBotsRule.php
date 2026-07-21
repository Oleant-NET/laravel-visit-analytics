<?php

namespace Oleant\VisitAnalytics\Rules\ExplicitBots;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

class ExplicitBotsRule implements RuleInterface
{
    /**
     * Identifies "Explicit bots" scanners
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
       $ua = $log->user_agent;

        // Skip analysis if User-Agent is not present
        if (empty($ua)) {
            return;
        }

        /** @var array $botSignatures List of substrings to identify bots */
        $botSignatures = $params['signatures'] ?? [];

        foreach ($botSignatures as $botSign) {
            // Ensure the signature is not an empty string before matching
            if (!empty($botSign) && stripos($ua, $botSign) !== false) {
                
                // Retrieve penalty weight from configuration
                $points = (int)($params['score'] ?? 100);
                
                $state->add($points, 'explicit_bot', [
                    'bot_signature' => $botSign
                ]);

                $state->addEvidence('bot_identity', $botSign);

                /**
                 * Flag as an official bot.
                 * This helps distinguish between 'malicious/unknown bots' and 
                 * 'known/official crawlers'.
                 */
                $state->isOfficialBot = true;

                // Stop further iteration within this analyzer once a match is found
                break;
            }
        }
    }
}