package securityaudit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseQwen3GuardStrictAndPolicy(t *testing.T) {
	tests := []struct {
		name, output string
		enabled      []string
		decision     EventDecision
		action       Action
		wantErr      bool
	}{
		{"safe", "Safety: Safe\nCategories: None", AllScannerIDs, EventPass, ActionAllow, false},
		{"controversial", "Safety: Controversial\nCategories: Violent", AllScannerIDs, EventFlag, ActionWarn, false},
		{"controversial pii escalates", "Safety: Controversial\nCategories: PII", AllScannerIDs, EventCritical, ActionBlock, false},
		{"unsafe", "Safety: Unsafe\nCategories: Jailbreak", AllScannerIDs, EventCritical, ActionBlock, false},
		{"unknown unsafe", "Safety: Unsafe\nCategories: Future Risk", AllScannerIDs, EventCritical, ActionBlock, false},
		{"disabled unsafe warns", "Safety: Unsafe\nCategories: Violent", []string{"PII"}, EventFlag, ActionWarn, false},
		{"extra explanation", "Safety: Safe\nCategories: None\nThis is safe", AllScannerIDs, EventPass, ActionAllow, false},
		{"duplicate", "Safety: Safe\nSafety: Safe", AllScannerIDs, "", "", true},
		{"duplicate categories", "Safety: Safe\nCategories: None\nCategories: PII", AllScannerIDs, "", "", true},
		{"missing categories", "Safety: Safe\n", AllScannerIDs, "", "", true},
		{"unknown safety", "Safety: Maybe\nCategories: PII", AllScannerIDs, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseQwen3Guard(tt.output, tt.enabled)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.decision, result.Decision)
			require.Equal(t, tt.action, result.Action)
		})
	}
}

func TestParseQwen3GuardIgnoresAuxiliaryResponseFields(t *testing.T) {
	result, err := ParseQwen3Guard("Safety: Unsafe\nCategories: Jailbreak\nRefusal: No", AllScannerIDs)
	require.NoError(t, err)
	require.Equal(t, "Unsafe", result.Safety)
	require.Equal(t, []string{"jailbreak"}, result.Categories)

	serialized, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(serialized), "Refusal")
	require.NotContains(t, string(serialized), "No")
}

func TestThresholdPolicyUsesNativeSafetyLevelsAndScannerScope(t *testing.T) {
	tests := []struct {
		name           string
		result         NormalizedResult
		flagThreshold  string
		blockThreshold string
		decision       EventDecision
		risk           RiskLevel
		action         Action
	}{
		{name: "default controversial flags", result: NormalizedResult{Safety: "Controversial", Categories: []string{"pii"}, MatchedScanners: []string{"pii"}}, flagThreshold: "Controversial", blockThreshold: "Unsafe", decision: EventFlag, risk: RiskMedium, action: ActionWarn},
		{name: "controversial block level blocks controversial", result: NormalizedResult{Safety: "Controversial", Categories: []string{"pii"}, MatchedScanners: []string{"pii"}}, flagThreshold: "Safe", blockThreshold: "Controversial", decision: EventCritical, risk: RiskCritical, action: ActionBlock},
		{name: "unsafe flag level allows controversial", result: NormalizedResult{Safety: "Controversial", Categories: []string{"pii"}, MatchedScanners: []string{"pii"}}, flagThreshold: "Unsafe", blockThreshold: "Unsafe", decision: EventPass, risk: RiskLow, action: ActionAllow},
		{name: "unsafe enabled category blocks", result: NormalizedResult{Safety: "Unsafe", Categories: []string{"jailbreak"}, MatchedScanners: []string{"jailbreak"}}, flagThreshold: "Controversial", blockThreshold: "Unsafe", decision: EventCritical, risk: RiskCritical, action: ActionBlock},
		{name: "unsafe disabled known category only flags", result: NormalizedResult{Safety: "Unsafe", Categories: []string{"jailbreak"}}, flagThreshold: "Controversial", blockThreshold: "Unsafe", decision: EventFlag, risk: RiskHigh, action: ActionWarn},
		{name: "unsafe unknown category blocks", result: NormalizedResult{Safety: "Unsafe", UnknownCategories: []string{"unknown:1234"}}, flagThreshold: "Controversial", blockThreshold: "Unsafe", decision: EventCritical, risk: RiskCritical, action: ActionBlock},
		{name: "safe threshold is honored", result: NormalizedResult{Safety: "Safe"}, flagThreshold: "Safe", blockThreshold: "Safe", decision: EventCritical, risk: RiskCritical, action: ActionBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyThresholdPolicy(&tt.result, tt.flagThreshold, tt.blockThreshold, nil)
			require.Equal(t, tt.decision, tt.result.Decision)
			require.Equal(t, tt.risk, tt.result.RiskLevel)
			require.Equal(t, tt.action, tt.result.Action)
		})
	}
}

func TestThresholdPolicySupportsPerCategoryOverrides(t *testing.T) {
	tests := []struct {
		name       string
		result     NormalizedResult
		thresholds map[string]CategoryThresholdConfig
		decision   EventDecision
	}{
		{
			name:       "compatibility pii override blocks controversial",
			result:     NormalizedResult{Safety: "Controversial", Categories: []string{"pii"}, MatchedScanners: []string{"pii"}},
			thresholds: DefaultCategoryThresholds(), decision: EventCritical,
		},
		{
			name:       "violent inherits global and flags controversial",
			result:     NormalizedResult{Safety: "Controversial", Categories: []string{"violent"}, MatchedScanners: []string{"violent"}},
			thresholds: DefaultCategoryThresholds(), decision: EventFlag,
		},
		{
			name:       "violent block override blocks controversial",
			result:     NormalizedResult{Safety: "Controversial", Categories: []string{"violent"}, MatchedScanners: []string{"violent"}},
			thresholds: map[string]CategoryThresholdConfig{"violent": {BlockThreshold: "Controversial"}}, decision: EventCritical,
		},
		{
			name:       "cleared pii override inherits global",
			result:     NormalizedResult{Safety: "Controversial", Categories: []string{"pii"}, MatchedScanners: []string{"pii"}},
			thresholds: map[string]CategoryThresholdConfig{}, decision: EventFlag,
		},
		{
			name:       "strictest matching category wins",
			result:     NormalizedResult{Safety: "Controversial", Categories: []string{"violent", "pii"}, MatchedScanners: []string{"violent", "pii"}},
			thresholds: map[string]CategoryThresholdConfig{"violent": {FlagThreshold: "Unsafe"}, "pii": {BlockThreshold: "Controversial"}}, decision: EventCritical,
		},
		{
			name:       "disabled category override cannot block",
			result:     NormalizedResult{Safety: "Controversial", Categories: []string{"pii"}},
			thresholds: map[string]CategoryThresholdConfig{"pii": {BlockThreshold: "Controversial"}}, decision: EventFlag,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyThresholdPolicy(&tt.result, DefaultFlagThreshold, DefaultBlockThreshold, tt.thresholds)
			require.Equal(t, tt.decision, tt.result.Decision)
		})
	}
}

func TestQwen3GuardOfficialCategoriesAliasesAndUnknownAreStable(t *testing.T) {
	official := "Violent, Non-violent Illegal Acts, Sexual Content or Sexual Acts, PII, Suicide & Self-Harm, Unethical Acts, Politically Sensitive Topics, Copyright Violation, Jailbreak"
	result, err := ParseQwen3Guard("Safety: Unsafe\nCategories: "+official, AllScannerIDs)
	require.NoError(t, err)
	require.Equal(t, AllScannerIDs, result.MatchedScanners)
	require.Empty(t, result.UnknownCategories)
	require.Equal(t, "priority", result.PolicyID)
	require.Equal(t, 1, result.PolicyVersion)

	aliases := map[string]string{
		"violence": "violent", "non_violent_illegal_acts": "non_violent_illegal_acts",
		"sexual": "sexual_content_or_sexual_acts", "personal identifiable information": "pii",
		"suicide/self harm": "suicide_and_self_harm", "unethical": "unethical_acts",
		"political": "politically_sensitive_topics", "copyright": "copyright_violation",
		"prompt injection": "jailbreak",
	}
	for alias, canonical := range aliases {
		require.Equal(t, canonical, NormalizeCategory(alias), alias)
	}

	const canary = "PROMPT_CANARY_RAW_UNKNOWN_CATEGORY"
	unknown, err := ParseQwen3Guard("Safety: Unsafe\nCategories: "+canary, AllScannerIDs)
	require.NoError(t, err)
	require.Len(t, unknown.UnknownCategories, 1)
	require.NotContains(t, unknown.UnknownCategories[0], "canary")
	require.NotContains(t, unknown.UnknownCategories[0], "raw")
	require.Contains(t, unknown.UnknownCategories[0], "unknown:")
}

func TestExtractOpenAIContentSupportsStringAndTextBlocks(t *testing.T) {
	content, err := extractOpenAIContent([]byte(`{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`))
	require.NoError(t, err)
	require.Equal(t, "Safety: Safe\nCategories: None", content)
	content, err = extractOpenAIContent([]byte(`{"choices":[{"message":{"content":[{"type":"text","text":"Safety: Safe"},{"type":"text","text":"Categories: None"}]}}]}`))
	require.NoError(t, err)
	require.Equal(t, "Safety: Safe\nCategories: None", content)
	for _, body := range []string{`{}`, `{"choices":[]}`, `{"choices":[{"message":{"content":null}}]}`} {
		_, err := extractOpenAIContent([]byte(body))
		require.Error(t, err)
	}
}

func TestAggregateRequiresEveryResult(t *testing.T) {
	_, err := AggregateResults([]*NormalizedResult{{Decision: EventPass, Action: ActionAllow}, nil}, 0)
	require.Error(t, err)
	result, err := AggregateResults([]*NormalizedResult{
		{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Categories: []string{"pii"}},
		{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Categories: []string{"jailbreak"}},
	}, 0)
	require.NoError(t, err)
	require.Equal(t, EventCritical, result.Decision)
	require.Equal(t, ActionBlock, result.Action)
	require.Equal(t, []string{"pii", "jailbreak"}, result.Categories)
}

func TestAggregateDeduplicatesFactsAndUsesMostSevereEndpointMetadata(t *testing.T) {
	result, err := AggregateResults([]*NormalizedResult{
		{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe", Categories: []string{"pii"}, MatchedScanners: []string{"pii"}, ScannerScores: map[string]float64{"pii": 0}, ScannerEvidence: map[string]string{"pii": "first"}, GuardEndpointID: "safe-node", ScannerVersion: "safe-version", PolicyID: "priority", PolicyVersion: 1},
		{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe", Categories: []string{"pii", "jailbreak"}, MatchedScanners: []string{"pii", "jailbreak"}, ScannerScores: map[string]float64{"pii": 1, "jailbreak": 1}, ScannerEvidence: map[string]string{"pii": "second", "jailbreak": "blocked"}, GuardEndpointID: "block-node", ScannerVersion: "block-version", PolicyID: "priority", PolicyVersion: 2},
	}, 7*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, []string{"pii", "jailbreak"}, result.Categories)
	require.Equal(t, []string{"pii", "jailbreak"}, result.MatchedScanners)
	require.Equal(t, "first", result.ScannerEvidence["pii"], "evidence is deterministically first-seen")
	require.Equal(t, "block-node", result.GuardEndpointID)
	require.Equal(t, "block-version", result.ScannerVersion)
	require.Equal(t, 2, result.PolicyVersion)
	require.Equal(t, 7, result.LatencyMS)
}

func TestIssueSummariesAreDeterministicRedactedDerivedDTOs(t *testing.T) {
	const canary = "PROMPT_CANARY_EVIDENCE_SECRET"
	result := NormalizedResult{
		Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock,
		Categories: []string{"jailbreak", "pii"}, MatchedScanners: []string{"pii"},
		ScannerScores: map[string]float64{"pii": 1}, ScannerEvidence: map[string]string{"pii": canary},
		UnknownCategories: []string{unknownCategoryID("future risk")},
	}
	summaries := BuildIssueSummaries(result)
	require.Len(t, summaries, 3, "known categories are not hidden merely because policy disabled one")
	raw, err := json.Marshal(summaries)
	require.NoError(t, err)
	require.NotContains(t, string(raw), canary)
	for _, summary := range summaries {
		require.NotEmpty(t, summary.Title)
		require.NotEmpty(t, summary.Description)
		require.NotEmpty(t, summary.Code)
		require.NotEmpty(t, summary.EvidenceHash)
	}
}
