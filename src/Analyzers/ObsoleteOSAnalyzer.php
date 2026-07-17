<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Analyzers\Base\AbstractAnalyzer;
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
class ObsoleteOSAnalyzer extends AbstractAnalyzer implements BotAnalyzerInterface
{
    /**
     * Analyzes the User-Agent for obsolete Operating System or Browser signatures.
     * 
     * The analysis is delegated to rules defined in the configuration. 
     * If the User-Agent is empty, the analysis is skipped.
     *
     * @param VisitLog $log The current visit log model.
     * @param AnalysisState $state The state object for accumulating results.
     * @param array $params Package configuration.
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        if (empty($log->user_agent)) {
            return;
        }

        /**
         * The executeRules() method is inherited from AbstractAnalyzer.
         * It iterates through the 'rules' provided in $params and applies them.
         */
        $this->executeRules($log, $state, $params);
    }
}