// Copyright LicenseSeat. All Rights Reserved.

#include "LicenseSeatModule.h"

#define LOCTEXT_NAMESPACE "FLicenseSeatModule"

void FLicenseSeatModule::StartupModule()
{
    // Module startup
    UE_LOG(LogTemp, Log, TEXT("LicenseSeat: Module started"));
}

void FLicenseSeatModule::ShutdownModule()
{
    // Module shutdown
    UE_LOG(LogTemp, Log, TEXT("LicenseSeat: Module shutdown"));
}

#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FLicenseSeatModule, LicenseSeat)
