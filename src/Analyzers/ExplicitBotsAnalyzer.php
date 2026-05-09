<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class ExplicitBotsAnalyzer
 * 
 * This analyzer performs a high-speed signature check against the User-Agent string.
 * It targets bots that openly identify themselves in the UA header (e.g., Googlebot, 
 * Bingbot, or common scrapers).
 * 
 * Since this is a "low-cost" string operation, it should typically be placed 
 * at the beginning of the analysis chain.
 */
class ExplicitBotsAnalyzer implements BotAnalyzerInterface
{
    /**
     * Analyze the User-Agent for explicit bot signatures.
     * 
     * If a match is found, the visitor is flagged as an 'official bot', which 
     * can be used to bypass more expensive behavioral or network checks later.
     *
     * @param VisitLog $log The current visit log being analyzed.
     * @param AnalysisState $state The mutable state object collecting scores and evidence.
     * @param array $params The package configuration array.
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        $ua = $log->user_agent;

        // Skip analysis if User-Agent is not present
        if (empty($ua)) {
            return;
        }

        /** @var array $botSignatures List of substrings to identify bots */
        $botSignatures = $params['explicit_bots'] ?? [];

        foreach ($botSignatures as $botSign) {
            // Ensure the signature is not an empty string before matching
            if (!empty($botSign) && stripos($ua, $botSign) !== false) {
                
                // Retrieve penalty weight from configuration
                $points = (int)($params['weights']['ua_explicit'] ?? 100);
                
                $state->add($points, 'explicit_bot', [
                    'bot_signature' => $botSign
                ]);

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