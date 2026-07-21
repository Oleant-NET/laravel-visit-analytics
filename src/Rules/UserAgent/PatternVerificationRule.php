<?php

namespace Oleant\VisitAnalytics\Rules\UserAgent;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Traits\VerifiesUserAgentSignature;

/**
 * Class PatternVerificationRule
 * 
 * Evaluates the User-Agent against a set of configured regex patterns.
 * Supports both standard matching and deep-verification for modern browsers 
 * that leverage Client Hints (Sec-CH-UA).
 */
class PatternVerificationRule implements RuleInterface
{
    use VerifiesUserAgentSignature;

    /**
     * Applies pattern matching and optional deep verification to the User-Agent.
     *
     * @param VisitLog $log The current visit log model.
     * @param AnalysisState $state The state object for accumulating results.
     * @param array $params Configuration: 'ua_regex_patterns', 'score'.
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $ua = trim((string)$log->user_agent);
        $patterns = $params['ua_regex_patterns'] ?? [];
        $headers = is_array($log->target_headers) ? $log->target_headers : [];

        foreach ($patterns as $key => $data) {
            $pattern = $data['pattern'] ?? $data;
            if (!str_starts_with($pattern, '/') || !preg_match('/\/[imsxu]*$/', $pattern)) {
                $delimiter = '/' . preg_quote($pattern, '/') . '/i';
            } else {
                $delimiter = $pattern;
            }
            $score = (int)($data['score'] ?? 0);
            $needsVerification = (bool)($data['requires_verification'] ?? false);

            // Execute regex check
            if (@preg_match($delimiter, $ua)) {
                
                if ($needsVerification) {
                    // Perform cross-reference with Client Hints / Fetch Metadata via trait
                    if (!$this->isSignatureVerified($ua, $headers, $params)) {
                        $failPoints = (int)($score ?? 80);
                        
                        $state->add($failPoints, "verification_failed_{$key}", [
                            'matched_pattern' => $pattern,
                            'check' => 'client_hints_mismatch'
                        ]);
                    }
                } else {
                    // Standard pattern match penalty
                    $state->add($score, "ua_match_{$key}", [
                        'matched_pattern' => $pattern
                    ]);
                }
            }
        }
    }
}