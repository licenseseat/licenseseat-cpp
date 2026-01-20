// Copyright LicenseSeat. All Rights Reserved.

using UnrealBuildTool;
using System.IO;

public class LicenseSeat : ModuleRules
{
    public LicenseSeat(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;

        // C++17 required for the SDK
        CppStandard = CppStandardVersion.Cpp17;

        // Public dependencies - UE modules we expose to users
        PublicDependencyModuleNames.AddRange(new string[]
        {
            "Core",
            "CoreUObject",
            "Engine"
        });

        // Private dependencies - UE modules we use internally
        PrivateDependencyModuleNames.AddRange(new string[]
        {
            "HTTP",
            "Json",
            "JsonUtilities"
        });

        // Third-party includes
        string ThirdPartyPath = Path.Combine(ModuleDirectory, "Private", "ThirdParty");

        PrivateIncludePaths.AddRange(new string[]
        {
            ThirdPartyPath,
            Path.Combine(ThirdPartyPath, "ed25519")
        });

        // No external dependencies needed!
        // - Ed25519 and SHA256 are vendored in ThirdParty
        // - HTTP uses UE's HTTP module
        // - JSON uses UE's JSON utilities

        // Platform-specific settings
        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            // Windows: Use WMI for device ID (already in UE)
        }
        else if (Target.Platform == UnrealTargetPlatform.Mac)
        {
            // macOS: Use IOKit for device ID
            PublicFrameworks.AddRange(new string[]
            {
                "CoreFoundation",
                "IOKit"
            });
        }
        else if (Target.Platform == UnrealTargetPlatform.Linux)
        {
            // Linux: Standard system info
        }
    }
}
