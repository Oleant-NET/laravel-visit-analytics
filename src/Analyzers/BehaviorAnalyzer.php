<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Support\Carbon;

class BehaviorAnalyzer implements BotAnalyzerInterface
{
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        if (!$log->ip_address) {
            return;
        }

        $this->checkVisitDepth($log, $state, $params);
        $this->checkRateLimit($log, $state, $params);
        $this->checkNavigationFlow($log, $state, $params);
        $this->checkUserAgentStability($log, $state, $params);
        $this->checkHeaderSetStability($log, $state, $params);
    }

    /**
     * Detects "single hit" scanners.
     * Only applies to direct document visits.
     */
    protected function checkVisitDepth(
        VisitLog $log,
        AnalysisState $state,
        array $params
    ): void {
        if ($this->isAjaxRequest($log)) {
            return;
        }

        if (!empty($log->referer)) {
            return;
        }

        $window = (int)($params['depth_check_window'] ?? 60);

        $baseTime = $this->ensureCarbon($log->created_at);

        $from = $baseTime->copy()->subMinutes($window);
        $to = $baseTime->copy()->addMinutes($window);

        $otherVisitsCount = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('id', '!=', $log->id)
            ->whereBetween('created_at', [$from, $to])
            ->count();

        if ($otherVisitsCount === 0) {
            $state->add(
                (int)($params['weights']['single_visit'] ?? 5),
                'single_page_scan',
                [
                    'visit_depth' => '1_page_only',
                ]
            );
        }
    }

    /**
     * Detects abnormal request bursts.
     * AJAX/widget traffic is ignored because SPA frameworks
     * legitimately produce many background requests.
     */
    protected function checkRateLimit(
        VisitLog $log,
        AnalysisState $state,
        array $params
    ): void {
        if ($this->isAjaxRequest($log)) {
            return;
        }

        $window = (int)($params['time_window'] ?? 5);

        $from = $this->ensureCarbon($log->created_at)
            ->copy()
            ->subMinutes($window);

        $historyCount = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->whereBetween('created_at', [$from, $log->created_at])
            ->where(function ($query) {
                $query
                    ->whereNull('target_headers')
                    ->orWhereNull('target_headers->x-requested-with');
            })
            ->count();

        $maxRate = (
            (int)($params['rate_limit_per_minute'] ?? 120)
            * $window
        );

        if ($historyCount > $maxRate) {
            $state->add(
                (int)($params['weights']['rate'] ?? 15),
                'high_request_rate',
                [
                    'request_rate_metric' => "{$historyCount}/{$window}min",
                ]
            );
        }
    }

    /**
     * Human navigation flow analysis.
     * SPA-safe and refresh-safe.
     */
    protected function checkNavigationFlow(
        VisitLog $log,
        AnalysisState $state,
        array $params
    ): void {
        $prev = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->orderByDesc('id')
            ->first();

        if (!$prev) {
            return;
        }

        $currentTime = $this->ensureCarbon($log->created_at);
        $prevTime = $this->ensureCarbon($prev->created_at);

        // Millisecond precision for SPA compatibility
        $diffMs = abs(
            $currentTime->diffInMilliseconds($prevTime)
        );

        $state->addEvidence('request_interval_ms', $diffMs);

        /**
         * -------------------------------------------------------
         * A. Speed Anomaly Detection
         * -------------------------------------------------------
         */

        $minIntervalMs = (int)(
            $params['min_interval_ms'] ?? 250
        );

        // Ignore AJAX/widget bursts completely
        if (
            !$this->isAjaxRequest($log)
            && !$this->isAjaxRequest($prev)
        ) {
            if ($diffMs < $minIntervalMs) {

                $baseWeight = (int)(
                    $params['weights']['speed_anomaly'] ?? 10
                );

                $wasPrevFast =
                    is_array($prev->bot_reasons)
                    && in_array(
                        'speed_anomaly',
                        $prev->bot_reasons,
                        true
                    );

                // Require repeated ultra-fast navigation
                // before treating it as suspicious
                if ($wasPrevFast) {
                    $state->add(
                        $baseWeight,
                        'speed_anomaly'
                    );
                }
            }
        }

        /**
         * -------------------------------------------------------
         * B. Referer Chain Validation
         * -------------------------------------------------------
         */

        if (empty($log->referer)) {

            // Direct navigation / bookmark / new tab
            $secFetchSite = $this->header(
                $log,
                'sec-fetch-site'
            );

            if ($secFetchSite === 'none') {
                $state->addEvidence(
                    'referer_source',
                    'direct_navigation'
                );

                return;
            }

            // Browser refresh — not suspicious
            if ($prev->url === $log->url) {

                $state->addEvidence(
                    'nav_type',
                    'page_refresh'
                );

                return;
            }

            // Missing referer on internal navigation
            // gets only a tiny soft score
            $penalty = (int)(
                $params['cumulative']['no_referer_increment'] ?? 5
            );

            $state->add(
                $penalty,
                'broken_referer_chain',
                [
                    'prev_page' => $prev->url,
                ]
            );
        }

        /**
         * -------------------------------------------------------
         * C. Real referer loop detection
         * -------------------------------------------------------
         */

        if (
            !empty($log->referer)
            && $log->referer === $log->url
            && !$this->isAjaxRequest($log)
        ) {
            // Only suspicious if repeated multiple times
            $sameUrlCount = VisitLog::query()
                ->where('ip_address', $log->ip_address)
                ->where('url', $log->url)
                ->where('referer', $log->url)
                ->where('id', '>=', max(1, $log->id - 10))
                ->count();

            if ($sameUrlCount >= 3) {
                $state->add(
                    10,
                    'referer_loop'
                );
            }
        }
    }

    /**
     * Detects if the User-Agent changes for the same IP within a short window.
     * Real users rarely switch browsers/devices mid-session.
     */
    protected function checkUserAgentStability(
        VisitLog $log,
        AnalysisState $state,
        array $params
    ): void {
        $window = (int)($params['ua_stability_window'] ?? 30);

        $from = $this->ensureCarbon($log->created_at)->copy()->subMinutes($window);

        $differentUA = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->where('created_at', '>=', $from)
            ->where('user_agent', '!=', $log->user_agent)
            ->orderByDesc('id')
            ->first();

        if ($differentUA) {
            $weight = (int)($params['weights']['ua_change_anomaly'] ?? 40);

            $state->add(
                $weight,
                'ua_change_anomaly',
                [
                    'previous_ua' => $differentUA->user_agent,
                    'current_ua'  => $log->user_agent,
                    'time_diff'   => $differentUA->created_at->diffForHumans($log->created_at),
                ]
            );
        }
    }

    /**
     * Detects changes to the fingerprint for a single IP address.
     * Real browsers maintain a stable set of headers throughout a session.
     */
    protected function checkHeaderSetStability(VisitLog $log, AnalysisState $state, array $params):void 
    {
        $window = (int)($params['header_stability_window'] ?? 30); // Minutes

        $from = $this->ensureCarbon($log->created_at)->copy()->subMinutes($window);

        $differentFingerprint = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->where('created_at', '>=', $from)
            ->where('fingerprint_hash', '!=', $log->fingerprint_hash)
            ->orderByDesc('id')
            ->first();

        if ($differentFingerprint) {
            $weight = (int)($params['weights']['header_set_anomaly'] ?? 30);

            $state->add(
                $weight,
                'header_set_anomaly',
                [
                    'time_diff'     => $differentFingerprint->created_at->diffForHumans($log->created_at),
                    'prev_keys'     => is_array($differentFingerprint->target_headers) ? array_keys($differentFingerprint->target_headers) : [],
                    'curr_keys'     => is_array($log->target_headers) ? array_keys($log->target_headers) : [],
                ]
            );
        }
    }

    /**
     * Detects AJAX/XHR/fetch requests.
     */
    protected function isAjaxRequest(VisitLog $log): bool
    {
        return (
            $this->header($log, 'x-requested-with')
                === 'XMLHttpRequest'
        );
    }

    /**
     * Safely read header from stored JSON.
     */
    protected function header(
        VisitLog $log,
        string $key
    ): ?string {
        if (!is_array($log->target_headers)) {
            return null;
        }

        return $log->target_headers[$key] ?? null;
    }

    protected function ensureCarbon($date): Carbon
    {
        return $date instanceof Carbon
            ? $date
            : Carbon::parse($date);
    }
}