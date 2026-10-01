namespace SupraChat.Core;

public static class AccessibilityContract
{
    public const string Schema = "suprachat-accessibility/v1";

    public static string PrimaryModifierName =>
        OperatingSystem.IsMacOS() ? "Command" : "Control";

    public static AccessibilityDescriptor Describe() => new(
        Schema,
        "SupraChat",
        PlatformName(),
        new AccessibilityHuman(
            KeyboardOnly: true,
            ScreenReaderSemantics: true,
            StableAutomationIds: true,
            SemanticHeadings: true,
            LabeledInputs: true,
            LiveStatusRegions: true,
            StateNeverColorOnly: true,
            SystemTheme: true,
            HighContrastFollowsPlatform: true,
            DpiRenderScaling: true,
            RequiredPointerGestures: false,
            RequiredCustomMotion: false,
            BrowserAccessibilityFallback: true,
            Shortcuts: new[]
            {
                $"{PrimaryModifierName}+1",
                $"{PrimaryModifierName}+2",
                $"{PrimaryModifierName}+3",
                $"{PrimaryModifierName}+L"
            }),
        new AccessibilityAutomation(
            ScreenScrapingRequired: false,
            DeterministicJson: true,
            StableExitCodes: true,
            SemanticCommands: true),
        new AccessibilityAgent(
            ScreenScrapingRequired: false,
            Protocol: "json-rpc-2.0-stdio",
            SemanticMethods: true,
            HumanConsentBoundariesPreserved: true),
        new AccessibilityQualification(
            ContractDocument: "ACCESSIBILITY.md",
            AccessibilityRegressionIsFailure: true));

    private static string PlatformName() =>
        OperatingSystem.IsWindows() ? "windows" :
        OperatingSystem.IsMacOS() ? "macos" :
        OperatingSystem.IsLinux() ? "linux" :
        "unknown";
}

public sealed record AccessibilityDescriptor(
    string Schema,
    string Product,
    string Platform,
    AccessibilityHuman Human,
    AccessibilityAutomation Automation,
    AccessibilityAgent Agent,
    AccessibilityQualification Qualification);

public sealed record AccessibilityHuman(
    bool KeyboardOnly,
    bool ScreenReaderSemantics,
    bool StableAutomationIds,
    bool SemanticHeadings,
    bool LabeledInputs,
    bool LiveStatusRegions,
    bool StateNeverColorOnly,
    bool SystemTheme,
    bool HighContrastFollowsPlatform,
    bool DpiRenderScaling,
    bool RequiredPointerGestures,
    bool RequiredCustomMotion,
    bool BrowserAccessibilityFallback,
    string[] Shortcuts);

public sealed record AccessibilityAutomation(
    bool ScreenScrapingRequired,
    bool DeterministicJson,
    bool StableExitCodes,
    bool SemanticCommands);

public sealed record AccessibilityAgent(
    bool ScreenScrapingRequired,
    string Protocol,
    bool SemanticMethods,
    bool HumanConsentBoundariesPreserved);

public sealed record AccessibilityQualification(
    string ContractDocument,
    bool AccessibilityRegressionIsFailure);
