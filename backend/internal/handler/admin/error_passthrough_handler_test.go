package admin

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type scopedPassthroughRepo struct{ rule *model.ErrorPassthroughRule }

func (r *scopedPassthroughRepo) List(context.Context) ([]*model.ErrorPassthroughRule, error) {
	if r.rule == nil {
		return []*model.ErrorPassthroughRule{}, nil
	}
	return []*model.ErrorPassthroughRule{r.rule}, nil
}
func (r *scopedPassthroughRepo) GetByID(context.Context, int64) (*model.ErrorPassthroughRule, error) {
	return r.rule, nil
}
func (r *scopedPassthroughRepo) Create(_ context.Context, rule *model.ErrorPassthroughRule) (*model.ErrorPassthroughRule, error) {
	rule.ID = 1
	r.rule = rule
	return rule, nil
}
func (r *scopedPassthroughRepo) Update(_ context.Context, rule *model.ErrorPassthroughRule) (*model.ErrorPassthroughRule, error) {
	r.rule = rule
	return rule, nil
}
func (r *scopedPassthroughRepo) Delete(context.Context, int64) error { r.rule = nil; return nil }

func TestErrorPassthroughAccountScopeCRUD(t *testing.T) {
	repo := &scopedPassthroughRepo{}
	svc := service.NewErrorPassthroughService(repo, nil)
	h := NewErrorPassthroughHandler(svc)
	router := gin.New()
	router.POST("/rules", h.Create)
	router.PUT("/rules/:id", h.Update)
	request := func(method, path, body string, status int) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		require.Equal(t, status, rec.Code, rec.Body.String())
	}
	request("POST", "/rules", `{"name":"scoped","account_ids":[7],"error_codes":[403]}`, 200)
	require.Equal(t, []int64{7}, repo.rule.AccountIDs)
	require.NotNil(t, svc.MatchRuleForAccount("kimi", 7, 403, nil))
	require.Nil(t, svc.MatchRuleForAccount("kimi", 8, 403, nil))
	request("PUT", "/rules/1", `{"priority":3}`, 200)
	require.Equal(t, []int64{7}, repo.rule.AccountIDs, "omitted scope is preserved")
	request("PUT", "/rules/1", `{"account_ids":[0]}`, 400)
	require.Equal(t, []int64{7}, repo.rule.AccountIDs)
	request("PUT", "/rules/1", `{"account_ids":[]}`, 200)
	require.Empty(t, repo.rule.AccountIDs)
	require.NotNil(t, svc.MatchRuleForAccount("kimi", 8, 403, nil), "clearing scope refreshes matching cache")
}
