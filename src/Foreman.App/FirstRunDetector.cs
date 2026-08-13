using System.IO;
using System.Windows;

namespace Foreman.App;

/// <summary>
/// On first launch, points users at the agent connection guide (the dashboard "Connect" tab).
/// </summary>
public static class FirstRunDetector
{
    private static readonly string _flagPath = Path.Combine(
        Foreman.Core.ProductIdentity.LocalDataRoot, "first-run-complete.flag");

    public static void RunIfNeeded(int mcpPort, string mcpToken, Action openConnectGuide)
    {
        if (File.Exists(_flagPath)) return;

        Directory.CreateDirectory(Path.GetDirectoryName(_flagPath)!);
        File.WriteAllText(_flagPath, DateTime.UtcNow.ToString("O"));

        var choice = MessageBox.Show(
            $"""
            Welcome to TraceBrake - a local safety monitor for AI coding agents.

            TraceBrake's MCP server is running on port {mcpPort}.

            Open the Connect Agent guide now?

            It can configure Claude Code and Codex automatically, and it shows
            copy-paste settings for other MCP-capable agents.
            """,
            "TraceBrake - First Run", MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (choice == MessageBoxResult.Yes)
        {
            openConnectGuide();
            return;
        }

        MessageBox.Show(
            $"""
            You can connect an agent later from the TraceBrake tray menu or dashboard.

            MCP URL:
              http://localhost:{mcpPort}/mcp

            The /mcp endpoint needs the bearer token in:
              %LocalAppData%\TraceBrake\mcp.token
            """,
            "TraceBrake - Connect Agent", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
