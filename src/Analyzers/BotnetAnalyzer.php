<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Analyzers\Base\AbstractAnalyzer;
use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class BotnetAnalyzer
 * * Analyzes distributed botnets by detecting fingerprint clusters
 * within the VisitLog database.
 */
class BotnetAnalyzer extends AbstractAnalyzer implements BotAnalyzerInterface
{
    /**
     * {@inheritdoc}
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        if ($state->isOfficialBot || empty($log->fingerprint_hash)) {
            return;
        }

        // The logic is now encapsulated in the base class
        $this->executeRules($log, $state, $params);
    }
}