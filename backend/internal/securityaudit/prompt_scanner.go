package securityaudit

import (
	"errors"
	"sort"
	"strings"
	"time"
)

func SplitRunes(value string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	segments := strings.Split(value, promptAuditPrioritySeparator)
	chunks := make([]string, 0, len(segments))
	for _, segment := range segments {
		runes := []rune(segment)
		for start := 0; start < len(runes); start += limit {
			end := start + limit
			if end > len(runes) {
				end = len(runes)
			}
			chunks = append(chunks, string(runes[start:end]))
		}
	}
	return chunks
}

// applyThresholdPolicy compares Qwen3Guard's native ordered safety levels.
// Only enabled or unknown categories may block; findings in disabled known
// categories are still recorded as flags for administrator review.
func applyThresholdPolicy(result *NormalizedResult, flagThreshold, blockThreshold string, categoryThresholds map[string]CategoryThresholdConfig) {
	if result == nil {
		return
	}
	level, levelValid := safetyLevelRank(result.Safety)
	flagLevel, flagValid := safetyLevelRank(flagThreshold)
	blockLevel, blockValid := safetyLevelRank(blockThreshold)
	if !levelValid || !flagValid || !blockValid {
		return
	}
	shouldBlock := false
	shouldFlag := false
	matched := make(map[string]struct{}, len(result.MatchedScanners))
	for _, scanner := range result.MatchedScanners {
		scanner = NormalizeCategory(scanner)
		matched[scanner] = struct{}{}
		categoryFlagLevel, categoryBlockLevel := flagLevel, blockLevel
		if thresholds, ok := categoryThresholds[scanner]; ok {
			if rank, valid := safetyLevelRank(thresholds.FlagThreshold); valid {
				categoryFlagLevel = rank
			}
			if rank, valid := safetyLevelRank(thresholds.BlockThreshold); valid {
				categoryBlockLevel = rank
			}
		}
		shouldBlock = shouldBlock || level >= categoryBlockLevel
		shouldFlag = shouldFlag || level >= categoryFlagLevel
	}
	for _, category := range result.Categories {
		if _, enabled := matched[NormalizeCategory(category)]; !enabled {
			shouldFlag = shouldFlag || level >= flagLevel
		}
	}
	if len(result.UnknownCategories) > 0 {
		shouldBlock = shouldBlock || level >= blockLevel
		shouldFlag = shouldFlag || level >= flagLevel
	}
	if len(result.Categories) == 0 && len(result.MatchedScanners) == 0 && len(result.UnknownCategories) == 0 {
		shouldBlock = level >= blockLevel
		shouldFlag = level >= flagLevel
	}
	switch {
	case shouldBlock:
		result.Decision = EventCritical
		result.RiskLevel = RiskCritical
		result.Action = ActionBlock
	case shouldFlag:
		result.Decision = EventFlag
		result.RiskLevel = RiskMedium
		if result.Safety == "Unsafe" {
			result.RiskLevel = RiskHigh
		}
		result.Action = ActionWarn
	default:
		result.Decision = EventPass
		result.RiskLevel = RiskLow
		result.Action = ActionAllow
	}
}

func AggregateResults(results []*NormalizedResult, latency time.Duration) (*NormalizedResult, error) {
	if len(results) == 0 {
		return nil, errors.New("prompt guard produced no complete result")
	}
	aggregated := &NormalizedResult{
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow,
		ScannerBackend: "qwen3guard-openai", Categories: []string{}, MatchedScanners: []string{},
		ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}, ChunkTotal: len(results),
		LatencyMS: int(latency.Milliseconds()),
	}
	categories := map[string]struct{}{}
	matched := map[string]struct{}{}
	unknown := map[string]struct{}{}
	for _, result := range results {
		if result == nil {
			return nil, errors.New("prompt guard partial result is not allowed")
		}
		if resultSeverity(result.Decision) > resultSeverity(aggregated.Decision) {
			aggregated.Decision = result.Decision
			aggregated.RiskLevel = result.RiskLevel
			aggregated.Action = result.Action
			aggregated.Safety = result.Safety
			aggregated.GuardEndpointID = result.GuardEndpointID
			aggregated.ScannerVersion = result.ScannerVersion
			aggregated.PolicyID = result.PolicyID
			aggregated.PolicyVersion = result.PolicyVersion
		}
		if aggregated.GuardEndpointID == "" {
			aggregated.GuardEndpointID = result.GuardEndpointID
			aggregated.ScannerVersion = result.ScannerVersion
			aggregated.PolicyID = result.PolicyID
			aggregated.PolicyVersion = result.PolicyVersion
		}
		for _, category := range result.Categories {
			categories[category] = struct{}{}
		}
		for _, scanner := range result.MatchedScanners {
			matched[scanner] = struct{}{}
		}
		for scanner, score := range result.ScannerScores {
			if score > aggregated.ScannerScores[scanner] {
				aggregated.ScannerScores[scanner] = score
			}
		}
		for scanner, evidence := range result.ScannerEvidence {
			if _, exists := aggregated.ScannerEvidence[scanner]; !exists {
				aggregated.ScannerEvidence[scanner] = RedactPreview(evidence, 160)
			}
		}
		for _, category := range result.UnknownCategories {
			unknown[category] = struct{}{}
		}
	}
	aggregated.Categories = orderedScannerKeys(categories)
	aggregated.MatchedScanners = orderedScannerKeys(matched)
	aggregated.UnknownCategories = sortedKeys(unknown)
	return aggregated, nil
}

func resultSeverity(decision EventDecision) int {
	switch decision {
	case EventCritical:
		return 3
	case EventFlag:
		return 2
	default:
		return 1
	}
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func orderedScannerKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	remaining := make(map[string]struct{}, len(values))
	for key := range values {
		remaining[key] = struct{}{}
	}
	for _, scannerID := range AllScannerIDs {
		if _, ok := remaining[scannerID]; ok {
			result = append(result, scannerID)
			delete(remaining, scannerID)
		}
	}
	result = append(result, sortedKeys(remaining)...)
	return result
}
