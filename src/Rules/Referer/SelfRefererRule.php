<?php

namespace Oleant\VisitAnalytics\Rules\Referer;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Traits\QueriesVisitHistory;
use Oleant\VisitAnalytics\Traits\NormalizesUrls;

/**
 * Class SelfRefererRule
 * 
 * Detects circular navigation loops and "impossible" self-referencing headers.
 * It differentiates between legitimate same-origin requests and malicious
 * or bot-generated navigation loops.
 */
class SelfRefererRule implements RuleInterface
{
    use QueriesVisitHistory, NormalizesUrls;

    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        if (empty($log->referer)) return;

        $urlParts = parse_url($log->url);
        $refParts = parse_url($log->referer);

        if (($urlParts['host'] ?? '') !== ($refParts['host'] ?? '')) return;
        if (($log->target_headers['sec-fetch-site'] ?? null) === 'same-origin') return;

        if ($this->areUrlsCircular($log->url, $log->referer)) {
            if (!$this->hasVisitedUrlBefore($log->ip_address, $log->url, $log->id)) {
                $state->add(100, 'impossible_self_referer', ['anomaly' => 'self_ref_on_first_visit']);
            } else {
                $score = $params['score'] ?? [];
                $state->add((int)($score ?? 50), 'referer_loop');
            }
        }
    }
}