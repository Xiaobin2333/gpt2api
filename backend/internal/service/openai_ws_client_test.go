package service

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCoderOpenAIWSClientDialer_ProxyHTTPClientReuse(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	c1, err := impl.proxyHTTPClient("http://127.0.0.1:8080")
	require.NoError(t, err)
	c2, err := impl.proxyHTTPClient("http://127.0.0.1:8080")
	require.NoError(t, err)
	require.Same(t, c1, c2, "同一代理地址应复用同一个 HTTP 客户端")

	c3, err := impl.proxyHTTPClient("http://127.0.0.1:8081")
	require.NoError(t, err)
	require.NotSame(t, c1, c3, "不同代理地址应分离客户端")
}

func TestCoderOpenAIWSClientDialer_ProxyHTTPClientInvalidURL(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	_, err := impl.proxyHTTPClient("://bad")
	require.Error(t, err)
}

func TestIsCodexOAuthWSSURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "official", url: "wss://chatgpt.com/backend-api/codex/responses", want: true},
		{name: "case insensitive", url: "WSS://CHATGPT.COM/backend-api/codex/responses", want: true},
		{name: "wrong scheme", url: "ws://chatgpt.com/backend-api/codex/responses", want: false},
		{name: "api key upstream", url: "wss://api.openai.com/v1/responses", want: false},
		{name: "deceptive hostname", url: "wss://chatgpt.com.evil.example/responses", want: false},
		{name: "missing hostname", url: "wss:///backend-api/codex/responses", want: false},
		{name: "invalid", url: "://bad", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isCodexOAuthWSSURL(tt.url))
		})
	}
}

func TestCoderOpenAIWSClientDialer_CodexDirectUsesFingerprintTransport(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	client, err := impl.httpClientForTarget("wss://chatgpt.com/backend-api/codex/responses", "")
	require.NoError(t, err)
	require.NotNil(t, client)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.DialTLSContext)
	require.Nil(t, transport.Proxy)
	require.False(t, transport.ForceAttemptHTTP2)

	reused, err := impl.codexHTTPClient("")
	require.NoError(t, err)
	require.Same(t, client, reused)
}

func TestCoderOpenAIWSClientDialer_CodexProxyIsIsolatedFromStandardProxy(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)
	proxy := "http://127.0.0.1:48080"

	codexClient, err := impl.httpClientForTarget("wss://chatgpt.com/backend-api/codex/responses", proxy)
	require.NoError(t, err)
	standardClient, err := impl.httpClientForTarget("wss://api.openai.com/v1/responses", proxy)
	require.NoError(t, err)
	require.NotSame(t, codexClient, standardClient)

	codexTransport, ok := codexClient.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, codexTransport.DialTLSContext)
	require.Nil(t, codexTransport.Proxy, "Codex CONNECT dialer owns proxy traversal")
	require.False(t, codexTransport.ForceAttemptHTTP2)

	standardTransport, ok := standardClient.Transport.(*http.Transport)
	require.True(t, ok)
	require.Nil(t, standardTransport.DialTLSContext)
	require.NotNil(t, standardTransport.Proxy)
}

func TestCoderOpenAIWSClientDialer_CodexSOCKS5NormalizesAndReuses(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	c1, err := impl.codexHTTPClient("socks5://127.0.0.1:1080")
	require.NoError(t, err)
	c2, err := impl.codexHTTPClient("socks5h://127.0.0.1:1080")
	require.NoError(t, err)
	require.Same(t, c1, c2)

	transport, ok := c1.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.DialTLSContext)
	require.Nil(t, transport.Proxy)
}

func TestCoderOpenAIWSClientDialer_CodexRejectsInvalidProxy(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	_, err := impl.httpClientForTarget("wss://chatgpt.com/backend-api/codex/responses", "ftp://127.0.0.1:21")
	require.ErrorContains(t, err, "unsupported proxy scheme")
}

func TestCoderOpenAIWSClientDialer_DirectNonCodexUsesDefaultClient(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	client, err := impl.httpClientForTarget("wss://api.openai.com/v1/responses", "")
	require.NoError(t, err)
	require.Nil(t, client)
}

func TestCoderOpenAIWSClientDialer_TransportMetricsSnapshot(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	_, err := impl.proxyHTTPClient("http://127.0.0.1:18080")
	require.NoError(t, err)
	_, err = impl.proxyHTTPClient("http://127.0.0.1:18080")
	require.NoError(t, err)
	_, err = impl.proxyHTTPClient("http://127.0.0.1:18081")
	require.NoError(t, err)

	snapshot := impl.SnapshotTransportMetrics()
	require.Equal(t, int64(1), snapshot.ProxyClientCacheHits)
	require.Equal(t, int64(2), snapshot.ProxyClientCacheMisses)
	require.InDelta(t, 1.0/3.0, snapshot.TransportReuseRatio, 0.0001)
}

func TestCoderOpenAIWSClientDialer_ProxyClientCacheCapacity(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	total := openAIWSProxyClientCacheMaxEntries + 32
	for i := 0; i < total; i++ {
		_, err := impl.proxyHTTPClient(fmt.Sprintf("http://127.0.0.1:%d", 20000+i))
		require.NoError(t, err)
	}

	impl.proxyMu.Lock()
	cacheSize := len(impl.proxyClients)
	impl.proxyMu.Unlock()

	require.LessOrEqual(t, cacheSize, openAIWSProxyClientCacheMaxEntries, "代理客户端缓存应受容量上限约束")
}

func TestCoderOpenAIWSClientDialer_ProxyClientCacheIdleTTL(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	oldProxy := "http://127.0.0.1:28080"
	_, err := impl.proxyHTTPClient(oldProxy)
	require.NoError(t, err)

	impl.proxyMu.Lock()
	oldEntry := impl.proxyClients[oldProxy]
	require.NotNil(t, oldEntry)
	oldEntry.lastUsedUnixNano = time.Now().Add(-openAIWSProxyClientCacheIdleTTL - time.Minute).UnixNano()
	impl.proxyMu.Unlock()

	// 触发一次新的代理获取，驱动 TTL 清理。
	_, err = impl.proxyHTTPClient("http://127.0.0.1:28081")
	require.NoError(t, err)

	impl.proxyMu.Lock()
	_, exists := impl.proxyClients[oldProxy]
	impl.proxyMu.Unlock()

	require.False(t, exists, "超过空闲 TTL 的代理客户端应被回收")
}

func TestCoderOpenAIWSClientDialer_ProxyTransportTLSHandshakeTimeout(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	client, err := impl.proxyHTTPClient("http://127.0.0.1:38080")
	require.NoError(t, err)
	require.NotNil(t, client)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport)
	require.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
}

func TestCoderOpenAIWSClientConn_DoesNotSupportIdlePingWithoutReader(t *testing.T) {
	require.False(t, (&coderOpenAIWSClientConn{}).SupportsIdlePingWithoutReader())
}
