<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class ObsoleteOSAnalyzer
 * 
 * Detects visitors reporting legacy operating systems that are no longer 
 * in common use by human visitors in 2026. Automated scripts and legacy 
 * botnets often rely on outdated User-Agent strings, making this a 
 * reliable heuristic for suspicion.
 */
class ObsoleteOSAnalyzer implements BotAnalyzerInterface
{
    /**
     * Analyzes the User-Agent for obsolete Operating System signatures.
     *
     * @param VisitLog $log The current visit log model.
     * @param AnalysisState $state The state object for accumulating results.
     * @param array $params Package configuration.
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        $ua = (string)$log->user_agent;

        /** 
         * Default patterns for obsolete systems.
         * Windows NT 5.x covers XP and Server 2003.
         * Windows NT 6.0-6.3 covers Vista, 7, 8, and 8.1.
         */
        $obsoleteOSPatterns = $params['target_os'] ?? [];

        /** 
         * Default patterns for obsolete systems.
         * Windows NT 5.x covers XP and Server 2003.
         * Windows NT 6.0-6.3 covers Vista, 7, 8, and 8.1.
         */
        $obsoleteBrowserPatterns = $params['target_browsers'] ?? [];

        foreach ($obsoleteOSPatterns as $pattern) {
            if (stripos($ua, $pattern) !== false) {
                $points = (int)($params['weights']['obsolete_os'] ?? 35);

                /**
                 * Add score and reason. 
                 * We record the specific pattern found as technical evidence.
                 */
                $state->add($points, 'obsolete_os', [
                    'os_signature' => $pattern
                ]);

                break;
            }
        }        
        
        foreach ($obsoleteBrowserPatterns as $pattern) {
            if (stripos($ua, $pattern) !== false) {
                $points = (int)($params['weights']['obsolete_browsers'] ?? 35);

                /**
                 * Add score and reason. 
                 * We record the specific pattern found as technical evidence.
                 */
                $state->add($points, 'obsolete_browsers', [
                    'browsers_signature' => $pattern
                ]);

                break;
            }
        }
    }
}
