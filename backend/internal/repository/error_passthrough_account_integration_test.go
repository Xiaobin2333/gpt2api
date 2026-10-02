//go:build integration

package repository

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/stretchr/testify/require"
)

func TestErrorPassthroughAccountScopePersistence(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	repo := NewErrorPassthroughRepository(client)
	rule, err := repo.Create(ctx, &model.ErrorPassthroughRule{
		Name: "account scope", Enabled: true, MatchMode: "any",
		ErrorCodes: []int{403}, AccountIDs: []int64{7, 8}, PassthroughCode: true,
	})
	require.NoError(t, err)
	// Use a fresh repository to verify persisted data rather than an in-memory copy.
	reloaded := NewErrorPassthroughRepository(client)
	got, err := reloaded.GetByID(ctx, rule.ID)
	require.NoError(t, err)
	require.Equal(t, []int64{7, 8}, got.AccountIDs)
	got.AccountIDs = []int64{9}
	_, err = repo.Update(ctx, got)
	require.NoError(t, err)
	got, err = reloaded.GetByID(ctx, rule.ID)
	require.NoError(t, err)
	require.Equal(t, []int64{9}, got.AccountIDs)
	got.AccountIDs = []int64{}
	_, err = repo.Update(ctx, got)
	require.NoError(t, err)
	got, err = reloaded.GetByID(ctx, rule.ID)
	require.NoError(t, err)
	require.NotNil(t, got.AccountIDs)
	require.Empty(t, got.AccountIDs, "clearing scope restores global behavior")
}
