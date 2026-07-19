<?php

namespace Oleant\VisitAnalytics\Rules\OutdatedBrowser;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Traits\ParsesBrowserInfo;

/**
 * Class OutdatedBrowserRule
 * 
 * Evaluates the browser version detected in the visit log against defined 
 * thresholds. It applies a penalty score if the browser is significantly 
 * older than the current reference version.
 */
class OutdatedBrowserRule implements RuleInterface
{
    use ParsesBrowserInfo;

    /**
     * Applies the outdated browser heuristic to the given visit log.
     *
     * @param VisitLog $log The current visit data.
     * @param AnalysisState $state The state object for accumulating scores and evidence.
     * @param array $params Configuration including current versions and scoring thresholds.
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        // Extract browser name and major version using the trait
        $browserData = $this->extractBrowserInfo($log);

        if (!$browserData) {
            return;
        }

        $browserName = $browserData['name'];
        $userVersion = $browserData['version'];
        $currentVersion = $params['current_versions'][$browserName] ?? null;

        /**
         * Skip if we lack reference data or the version information is invalid.
         */
        if (!$currentVersion || $userVersion <= 0) {
            return;
        }

        $diff = $currentVersion - $userVersion;
        
        /**
         * No penalty is applied if the user's browser version is 
         * current or newer than the reference.
         */
        if ($diff <= 0) {
            return;
        }

        $appliedScore = 0;
        $appliedThreshold = '';

        /**
         * Iterate through scoring thresholds. 
         * The loop ensures the most severe applicable penalty is selected.
         */
        foreach ($params['scoring'] as $level => $rules) {
            if ($diff >= $rules['diff']) {
                $appliedScore = $rules['score'];
                $appliedThreshold = $level;
            }
        }

        if ($appliedScore > 0) {
            $state->add($appliedScore, 'outdated_browser', [
                'browser'        => $browserName,
                'user_version'   => $userVersion,
                'target_version' => $currentVersion,
                'version_lag'    => $diff,
                'severity_level' => $appliedThreshold
            ]);
        }
    }
}