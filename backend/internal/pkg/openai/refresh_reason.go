package openai

import "context"

// RefreshReason is diagnostic metadata used by Codex 0.166.0's OAuth client.
// It never changes token validity or refresh eligibility.
type RefreshReason string

const (
	RefreshReasonProactiveExpiry      RefreshReason = "proactive_expiry"
	RefreshReasonScheduled            RefreshReason = "scheduled"
	RefreshReasonUnauthorizedRecovery RefreshReason = "unauthorized_recovery"
	RefreshReasonForced               RefreshReason = "forced"
)

type refreshReasonContextKey struct{}

func WithRefreshReason(ctx context.Context, reason RefreshReason) context.Context {
	return context.WithValue(ctx, refreshReasonContextKey{}, reason)
}

func RefreshReasonFromContext(ctx context.Context) RefreshReason {
	reason, _ := ctx.Value(refreshReasonContextKey{}).(RefreshReason)
	switch reason {
	case RefreshReasonProactiveExpiry, RefreshReasonScheduled, RefreshReasonUnauthorizedRecovery:
		return reason
	default:
		return RefreshReasonForced
	}
}
