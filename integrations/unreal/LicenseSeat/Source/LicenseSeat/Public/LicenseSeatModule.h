// Copyright LicenseSeat. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "Modules/ModuleManager.h"

/**
 * LicenseSeat Module
 *
 * Provides license validation and management for Unreal Engine projects.
 * Uses native UE HTTP and JSON - no external dependencies required.
 */
class FLicenseSeatModule : public IModuleInterface
{
public:
    /** IModuleInterface implementation */
    virtual void StartupModule() override;
    virtual void ShutdownModule() override;

    /**
     * Get the module instance
     */
    static FLicenseSeatModule& Get()
    {
        return FModuleManager::LoadModuleChecked<FLicenseSeatModule>("LicenseSeat");
    }

    /**
     * Check if the module is loaded
     */
    static bool IsAvailable()
    {
        return FModuleManager::Get().IsModuleLoaded("LicenseSeat");
    }
};
