<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Analyzers\Base\AbstractAnalyzer;
use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class HeaderIntegrityAnalyzer
 *
 * Validates the presence and consistency of HTTP headers against standard browser profiles.
 * 
 * This analyzer checks if the request contains mandatory headers that legitimate browsers 
 * typically include. It uses a weighted scoring system where missing critical headers 
 * (like Fetch Metadata or Client Hints) significantly increase the threat score.
 */
class HeaderIntegrityAnalyzer extends AbstractAnalyzer implements BotAnalyzerInterface
{
    /**
     * Analyze the integrity of the request headers.
     *
     * @param VisitLog $log The visit log instance (target_headers is already cast to array).
     * @param AnalysisState $state The state object for collecting scores and evidence.
     * @param array $params Configuration for this analyzer (header_integrity section).
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        // The logic is now encapsulated in the base class
        $this->executeRules($log, $state, $params);
    }


}