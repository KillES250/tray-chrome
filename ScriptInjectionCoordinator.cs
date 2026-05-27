using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;

namespace TrayChrome
{
    internal sealed class ScriptInjectionCoordinator
    {
        private readonly MainWindow window;
        private readonly string configPath;
        private readonly List<string> addedScriptIds = new List<string>();
        private List<ScriptRule> rules = new List<ScriptRule>();
        private ActiveRule? activeRule;
        private bool handlerAttached;
        private CoreWebView2? boundCore;
        private CancellationTokenSource? injectCts;

        public ScriptInjectionCoordinator(MainWindow window)
        {
            this.window = window;
            configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "script-intercepts.json");
        }

        public async Task InitializeAsync()
        {
            if (window.webView != null)
            {
                window.webView.CoreWebView2InitializationCompleted += OnCoreInitialized;
            }

            for (int i = 0; i < 80; i++)
            {
                if (window.webView?.CoreWebView2 != null)
                {
                    AttachHandlers(window.webView.CoreWebView2);
                    return;
                }

                await Task.Delay(100);
            }
        }

        /// <summary>
        /// WebView2 被重建后调用，重新绑定事件到新的 CoreWebView2
        /// </summary>
        public void RebindToWebView()
        {
            // 清理旧绑定
            injectCts?.Cancel();
            injectCts = null;
            if (boundCore != null)
            {
                boundCore.WebResourceRequested -= OnWebResourceRequested;
                boundCore.NavigationStarting -= OnNavigationStarting;
                boundCore = null;
            }
            handlerAttached = false;
            addedScriptIds.Clear();
            activeRule = null;

            // 重新绑定到新 webView
            if (window.webView != null)
            {
                window.webView.CoreWebView2InitializationCompleted += OnCoreInitialized;

                var core = window.webView.CoreWebView2;
                if (core != null)
                {
                    AttachHandlers(core);
                }
            }
        }

        private void OnCoreInitialized(object? sender, CoreWebView2InitializationCompletedEventArgs e)
        {
            if (!e.IsSuccess)
            {
                return;
            }

            var core = window.webView?.CoreWebView2;
            if (core != null)
            {
                AttachHandlers(core);
            }
        }

        private void AttachHandlers(CoreWebView2 core)
        {
            if (handlerAttached)
            {
                return;
            }

            core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.Script);
            core.WebResourceRequested += OnWebResourceRequested;
            core.NavigationStarting += OnNavigationStarting;
            boundCore = core;
            handlerAttached = true;
        }

        private async void OnNavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
        {
            // 取消上一次尚未完成的注入
            injectCts?.Cancel();
            injectCts = new CancellationTokenSource();
            var ct = injectCts.Token;

            string uri = e.Uri;

            try
            {
                // 文件 I/O 移到后台线程，避免阻塞导航
                ActiveRule? matched = await Task.Run(() =>
                {
                    LoadConfig();
                    return MatchRule(uri);
                }, ct);

                if (ct.IsCancellationRequested) return;

                activeRule = matched;
                await PrepareInjectScriptsOnStartedAsync(ct);
            }
            catch (OperationCanceledException)
            {
                // 导航被取消，忽略
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"脚本注入异常: {ex.Message}");
            }
        }

        private async Task PrepareInjectScriptsOnStartedAsync(CancellationToken ct)
        {
            var core = window.webView?.CoreWebView2;
            if (core == null)
            {
                return;
            }

            // 移除之前注册的脚本
            foreach (var id in addedScriptIds)
            {
                core.RemoveScriptToExecuteOnDocumentCreated(id);
            }
            addedScriptIds.Clear();

            if (activeRule == null)
            {
                return;
            }

            foreach (var script in activeRule.InjectScripts)
            {
                if (ct.IsCancellationRequested)
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(script))
                {
                    continue;
                }

                string id = await core.AddScriptToExecuteOnDocumentCreatedAsync(script);
                addedScriptIds.Add(id);
                await TryExecuteNowAsync(core, script);
            }
        }

        private static async Task TryExecuteNowAsync(CoreWebView2 core, string script)
        {
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    await core.ExecuteScriptAsync(script);
                    return;
                }
                catch
                {
                    await Task.Delay(60);
                }
            }
        }

        private void OnWebResourceRequested(object? sender, CoreWebView2WebResourceRequestedEventArgs e)
        {
            var core = window.webView?.CoreWebView2;
            if (core == null || activeRule == null)
            {
                return;
            }

            string? uri = e.Request?.Uri;
            if (string.IsNullOrWhiteSpace(uri))
            {
                return;
            }

            foreach (var pattern in activeRule.InterceptPatterns)
            {
                if (!IsWildcardMatch(uri, pattern))
                {
                    continue;
                }

                e.Response = core.Environment.CreateWebResourceResponse(
                    new MemoryStream(Array.Empty<byte>()),
                    200,
                    "OK",
                    "Content-Type: application/javascript; charset=utf-8");
                return;
            }
        }

        private void LoadConfig()
        {
            rules.Clear();
            if (!File.Exists(configPath))
            {
                return;
            }

            try
            {
                string json = File.ReadAllText(configPath);
                var cfg = JsonSerializer.Deserialize<ScriptConfig>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (cfg?.Rules != null)
                {
                    rules = cfg.Rules;
                }
            }
            catch
            {
                rules.Clear();
            }
        }

        private ActiveRule? MatchRule(string navigationUri)
        {
            if (!Uri.TryCreate(navigationUri, UriKind.Absolute, out var uri))
            {
                return null;
            }

            foreach (var rule in rules)
            {
                if (!IsHostMatched(uri.Host, rule.Domains))
                {
                    continue;
                }

                var active = new ActiveRule();
                foreach (var pattern in rule.InterceptJs)
                {
                    if (!string.IsNullOrWhiteSpace(pattern))
                    {
                        active.InterceptPatterns.Add(pattern.Trim());
                    }
                }

                foreach (var inject in rule.InjectJs)
                {
                    string path = ResolvePath(inject);
                    if (File.Exists(path))
                    {
                        active.InjectScripts.Add(File.ReadAllText(path));
                    }
                }

                return active;
            }

            return null;
        }

        private string ResolvePath(string value)
        {
            if (Path.IsPathRooted(value))
            {
                return value;
            }

            string fromBase = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, value);
            if (File.Exists(fromBase))
            {
                return fromBase;
            }

            return Path.Combine(Directory.GetCurrentDirectory(), value);
        }

        private static bool IsHostMatched(string host, List<string> patterns)
        {
            foreach (var raw in patterns)
            {
                if (string.IsNullOrWhiteSpace(raw))
                {
                    continue;
                }

                string value = raw.Trim();
                if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    if (Uri.TryCreate(value, UriKind.Absolute, out var u))
                    {
                        value = u.Host;
                    }
                }

                if (value == "*" || string.Equals(host, value, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (value.StartsWith("*.", StringComparison.Ordinal) &&
                    host.EndsWith(value.Substring(1), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsWildcardMatch(string text, string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern))
            {
                return false;
            }

            if (pattern == "*")
            {
                return true;
            }

            if (!pattern.Contains('*'))
            {
                return text.Contains(pattern, StringComparison.OrdinalIgnoreCase);
            }

            int pos = 0;
            foreach (var part in pattern.Split('*', StringSplitOptions.RemoveEmptyEntries))
            {
                int idx = text.IndexOf(part, pos, StringComparison.OrdinalIgnoreCase);
                if (idx < 0)
                {
                    return false;
                }
                pos = idx + part.Length;
            }
            return true;
        }

        private sealed class ScriptConfig
        {
            public List<ScriptRule> Rules { get; set; } = new List<ScriptRule>();
        }

        private sealed class ScriptRule
        {
            public List<string> Domains { get; set; } = new List<string>();
            public List<string> InterceptJs { get; set; } = new List<string>();
            public List<string> LoadJs { get; set; } = new List<string>();
            public List<string> InjectJs { get; set; } = new List<string>();
        }

        private sealed class ActiveRule
        {
            public List<string> InterceptPatterns { get; } = new List<string>();
            public List<string> InjectScripts { get; } = new List<string>();
        }
    }
}
