<?php

namespace Oleant\VisitAnalytics\Traits;

trait VerifiesUserAgentSignature
{
    /**
     * Shared logic to verify consistency between UA string and Client Hints.
     */
    protected function isSignatureVerified(string $ua, array $headers, array $params): bool
    {
        $headers = array_change_key_case($headers, CASE_LOWER);

        preg_match('/(?:Chrome|Edg|Chromium)\/([0-9]+)/', $ua, $uaMatches);
        $uaMajor = $uaMatches[1] ?? null;

        // Modern Chromium (v100+) check
        if ($uaMajor && (int)$uaMajor >= 100 && !isset($headers['sec-ch-ua'])) {
            return false;
        }

        // Version Consistency
        if ($uaMajor && isset($headers['sec-ch-ua'])) {
            if (!str_contains($headers['sec-ch-ua'], "v=\"$uaMajor\"")) {
                return false;
            }
        }

        // OS Consistency
        if (isset($headers['sec-ch-ua-platform'])) {
            $platform = trim($headers['sec-ch-ua-platform'], '" ');
            $osMap = $params['os_mapping'] ?? [];

            foreach ($osMap as $uaToken => $hintToken) {
                if (stripos($ua, (string)$uaToken) !== false) {
                    if ($platform !== $hintToken) return false;
                    break;
                }
            }
        }

        return true;
    }
}