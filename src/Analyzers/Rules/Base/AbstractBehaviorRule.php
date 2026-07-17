<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Base;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Support\Carbon;

/**
 * Abstract Class AbstractBehaviorRule
 * 
 * Base class for all behavioral analysis rules. Provides shared utility methods
 * for request inspection and data normalization.
 */
abstract class AbstractBehaviorRule implements RuleInterface
{
    /**
     * Detects if the request was made via AJAX/XHR/Fetch.
     * 
     * @param VisitLog $log
     * @return bool
     */
    protected function isAjaxRequest(VisitLog $log): bool
    {
        return $this->header($log, 'x-requested-with') === 'XMLHttpRequest';
    }

    /**
     * Safely retrieves a specific header from the stored JSON headers.
     * 
     * @param VisitLog $log
     * @param string $key
     * @return string|null
     */
    protected function header(VisitLog $log, string $key): ?string
    {
        if (!is_array($log->target_headers)) {
            return null;
        }

        return $log->target_headers[$key] ?? null;
    }

    /**
     * Ensures the provided date is a Carbon instance.
     * 
     * @param mixed $date
     * @return Carbon
     */
    protected function ensureCarbon($date): Carbon
    {
        return $date instanceof Carbon ? $date : Carbon::parse($date);
    }
}