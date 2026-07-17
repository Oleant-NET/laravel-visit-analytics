<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Analyzers\Base\AbstractAnalyzer;
use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class UserAgentAnalyzer
 * 
 * Provides an advanced evaluation of User-Agent integrity.
 * 
 * This analyzer acts as an execution engine that processes the visit log through 
 * a series of configured rules. It combines pattern matching, browser engine 
 * verification, and cross-reference checks with modern Client Hints (Sec-CH-UA) 
 * to detect sophisticated bot signatures.
 * 
 * Rule execution is delegated to the AbstractAnalyzer, allowing for highly 
 * dynamic and configurable analysis chains.
 */
class UserAgentAnalyzer extends AbstractAnalyzer implements BotAnalyzerInterface
{
    /**
     * Main entry point for User-Agent analysis.
     *
     * This method orchestrates the analysis by executing the rule chain 
     * defined in the $params array.
     *
     * @param VisitLog $log The current visit log model to analyze.
     * @param AnalysisState $state The state object for accumulating scores and evidence.
     * @param array $params Configuration parameters, including 'rules' to be executed.
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        /**
         * The rule chain is executed via the base AbstractAnalyzer.
         * Rules are expected to be passed via $params['rules'], which allows 
         * for flexible, configuration-driven analysis pipelines.
         */
        $this->executeRules($log, $state, $params);
    }
}