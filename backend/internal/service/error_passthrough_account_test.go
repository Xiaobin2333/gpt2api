package service

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestErrorPassthroughAccountScopeAndPriority(t *testing.T) {
	global := &model.ErrorPassthroughRule{ID: 10, Enabled: true, Priority: 20, ErrorCodes: []int{403}, MatchMode: "any"}
	account := &model.ErrorPassthroughRule{ID: 20, Enabled: true, Priority: 10, AccountIDs: []int64{7, 8}, Platforms: []string{PlatformKimi}, ErrorCodes: []int{403}, Keywords: []string{"quota"}, MatchMode: "all"}
	svc := &ErrorPassthroughService{}
	svc.setLocalCache([]*model.ErrorPassthroughRule{global, account})
	for _, tt := range []struct {
		name     string
		id       int64
		platform string
		body     string
		want     int64
	}{
		{"account wins", 7, PlatformKimi, "QUOTA exceeded", 20},
		{"second scoped account", 8, PlatformKimi, "quota", 20},
		{"other account uses global", 9, PlatformKimi, "quota", 10},
		{"unknown account uses global", 0, PlatformKimi, "quota", 10},
		{"platform still required", 7, PlatformOpenAI, "quota", 10},
		{"all conditions still required", 7, PlatformKimi, "concurrency", 10},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rule := svc.MatchRuleForAccount(tt.platform, tt.id, 403, []byte(tt.body))
			require.NotNil(t, rule)
			require.Equal(t, tt.want, rule.ID)
		})
	}
	require.Equal(t, global, svc.MatchRule(PlatformKimi, 403, []byte("quota")))
	global.Priority = 5
	svc.setLocalCache([]*model.ErrorPassthroughRule{account, global})
	require.Equal(t, global, svc.MatchRuleForAccount(PlatformKimi, 7, 403, []byte("quota")))
	global.Priority = account.Priority
	svc.setLocalCache([]*model.ErrorPassthroughRule{account, global})
	require.Equal(t, global, svc.MatchRuleForAccount(PlatformKimi, 7, 403, []byte("quota")), "ties use ascending rule ID")
	global.Enabled = false
	require.Equal(t, account, svc.MatchRuleForAccount(PlatformKimi, 7, 403, []byte("quota")))
	require.Nil(t, svc.MatchRuleForAccount(PlatformKimi, 9, 403, []byte("quota")))
}

func TestErrorPassthroughAccountFollowsFailoverAndMonitoringEvent(t *testing.T) {
	message := "account quota"
	accountRule := &model.ErrorPassthroughRule{ID: 1, Enabled: true, AccountIDs: []int64{7}, Platforms: []string{PlatformKimi}, ErrorCodes: []int{403}, MatchMode: "any", PassthroughCode: true, CustomMessage: &message, SkipMonitoring: true}
	svc := &ErrorPassthroughService{}
	svc.setLocalCache([]*model.ErrorPassthroughRule{accountRule})
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	BindErrorPassthroughService(c, svc)
	selectAccount := func(id int64) {
		ctx := context.WithValue(context.Background(), ctxkey.AccountID, id)
		ctx = context.WithValue(ctx, ctxkey.Platform, PlatformKimi)
		c.Request = httptest.NewRequest("POST", "/v1/chat/completions", nil).WithContext(ctx)
	}
	selectAccount(7)
	status, _, msg, matched := applyErrorPassthroughRule(c, PlatformOpenAI, 403, []byte("quota"), 502, "upstream_error", "default")
	require.True(t, matched)
	require.Equal(t, 403, status)
	require.Equal(t, message, msg)
	selectAccount(8)
	_, _, msg, matched = applyErrorPassthroughRule(c, PlatformOpenAI, 403, []byte("quota"), 502, "upstream_error", "default")
	require.False(t, matched)
	require.Equal(t, "default", msg)
	for _, id := range []int64{7, 8} {
		ev := &OpsUpstreamErrorEvent{AccountID: id, Platform: PlatformKimi, UpstreamStatusCode: 403, Message: "quota"}
		checkSkipMonitoringForUpstreamEvent(c, ev)
		require.Equal(t, id == 7, ev.SkipMonitoring, "event account takes precedence over current request account")
	}
	require.Nil(t, svc.MatchRuleForRequest(nil, PlatformKimi, 403, []byte("quota")))
}
