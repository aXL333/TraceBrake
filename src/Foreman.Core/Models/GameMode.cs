namespace Foreman.Core.Models;

/// <summary>
/// Mirror of the Win32 <c>QUERY_USER_NOTIFICATION_STATE</c> returned by <c>SHQueryUserNotificationState</c>
/// — the same signal Windows itself uses to decide whether to show toast notifications.
/// </summary>
public enum UserNotificationState
{
    NotPresent           = 1,
    Busy                 = 2,   // a full-screen (non-D3D) app is running
    RunningD3DFullScreen = 3,   // a full-screen DirectX app — i.e. a game
    PresentationMode     = 4,   // presentation mode (projecting)
    AcceptsNotifications = 5,   // normal desktop — notifications are fine
    QuietTime            = 6,
    App                  = 7,
}

/// <summary>Game-mode preferences: pause TraceBrake's on-screen interruptions while a game/fullscreen app is active.</summary>
public sealed class GameModeSettings
{
    /// <summary>Auto-detect a fullscreen game/app and pause TraceBrake's tray popups + alarm windows while it's active.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Even in game mode, still let Critical alerts interrupt on screen. Off by default — the whole point
    /// is not to barge in over a game — but a security-conscious operator can opt the most serious alerts in.
    /// </summary>
    public bool AllowCriticalBreakThrough { get; set; } = false;
}

/// <summary>
/// Pure game-mode decisions (testable). The actual SHQueryUserNotificationState P/Invoke lives in the app
/// shell (GameModeWatcher); this just maps the state and decides whether an alert may surface on screen.
/// </summary>
public static class GameModePolicy
{
    /// <summary>True for the states that mean a fullscreen/game/presentation app is active.</summary>
    public static bool IsFullscreen(UserNotificationState state) =>
        state is UserNotificationState.Busy
              or UserNotificationState.RunningD3DFullScreen
              or UserNotificationState.PresentationMode;

    /// <summary>
    /// Whether an alert may visually SURFACE (tray balloon / alarm window) right now. In active game mode,
    /// popups are paused unless the operator opted Critical break-through in. Detection, logging, counts and
    /// escalation are never affected — only the on-screen interruption is held (and surfaced as a digest on exit).
    /// </summary>
    public static bool ShouldSurface(ForemanSeverity severity, GameModeSettings settings, bool gameModeActive)
    {
        if (!gameModeActive || !settings.Enabled) return true;
        return settings.AllowCriticalBreakThrough && severity >= ForemanSeverity.Critical;
    }
}
