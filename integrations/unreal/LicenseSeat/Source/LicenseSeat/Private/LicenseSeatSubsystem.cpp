// Copyright LicenseSeat. All Rights Reserved.

#include "LicenseSeatSubsystem.h"
#include "HttpModule.h"
#include "Interfaces/IHttpRequest.h"
#include "Interfaces/IHttpResponse.h"
#include "Dom/JsonObject.h"
#include "Serialization/JsonReader.h"
#include "Serialization/JsonSerializer.h"
#include "Misc/Guid.h"
#include "HAL/PlatformMisc.h"
#include "TimerManager.h"

// Include vendored crypto (in ThirdParty folder)
extern "C" {
#include "ed25519.h"
}
#include "picosha2.h"

void ULicenseSeatSubsystem::Initialize(FSubsystemCollectionBase& Collection)
{
    Super::Initialize(Collection);
    UE_LOG(LogTemp, Log, TEXT("LicenseSeat: Subsystem initialized"));
}

void ULicenseSeatSubsystem::Deinitialize()
{
    StopAutoValidation();
    Super::Deinitialize();
    UE_LOG(LogTemp, Log, TEXT("LicenseSeat: Subsystem deinitialized"));
}

void ULicenseSeatSubsystem::InitializeWithConfig(const FLicenseSeatConfig& Config)
{
    CurrentConfig = Config;
    bIsInitialized = true;
    UE_LOG(LogTemp, Log, TEXT("LicenseSeat: Configured with product: %s"), *Config.ProductSlug);
}

FLicenseValidationResult ULicenseSeatSubsystem::Validate(const FString& LicenseKey)
{
    // For synchronous API, we'll use a blocking approach
    // This is not ideal for game threads - prefer ValidateAsync
    FLicenseValidationResult Result;
    Result.bValid = false;
    Result.LicenseKey = LicenseKey;

    if (!bIsInitialized)
    {
        Result.Reason = TEXT("LicenseSeat not initialized");
        return Result;
    }

    // Build request body
    TSharedPtr<FJsonObject> RequestJson = MakeShareable(new FJsonObject);
    RequestJson->SetStringField(TEXT("license_key"), LicenseKey);
    RequestJson->SetStringField(TEXT("device_identifier"), GetDeviceId());
    if (!CurrentConfig.ProductSlug.IsEmpty())
    {
        RequestJson->SetStringField(TEXT("product_slug"), CurrentConfig.ProductSlug);
    }

    FString RequestBody;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&RequestBody);
    FJsonSerializer::Serialize(RequestJson.ToSharedRef(), Writer);

    // Make synchronous request (blocking - use with caution)
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(CurrentConfig.ApiUrl + TEXT("/licenses/validate"));
    Request->SetVerb(TEXT("POST"));
    Request->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    Request->SetHeader(TEXT("Authorization"), FString::Printf(TEXT("Bearer %s"), *CurrentConfig.ApiKey));
    Request->SetContentAsString(RequestBody);

    // Process request synchronously
    Request->ProcessRequest();

    // Wait for completion (blocks!)
    double StartTime = FPlatformTime::Seconds();
    while (Request->GetStatus() == EHttpRequestStatus::Processing)
    {
        FPlatformProcess::Sleep(0.01f);
        if (FPlatformTime::Seconds() - StartTime > 30.0)
        {
            Result.Reason = TEXT("Request timeout");
            return Result;
        }
    }

    if (Request->GetStatus() == EHttpRequestStatus::Succeeded)
    {
        FString Response = Request->GetResponse()->GetContentAsString();
        Result = ParseValidationResponse(Response);
    }
    else
    {
        Result.Reason = TEXT("Network error");
    }

    CurrentStatus = Result;
    return Result;
}

FLicenseActivationResult ULicenseSeatSubsystem::Activate(const FString& LicenseKey)
{
    FLicenseActivationResult Result;
    Result.bSuccess = false;
    Result.DeviceId = GetDeviceId();

    if (!bIsInitialized)
    {
        Result.ErrorMessage = TEXT("LicenseSeat not initialized");
        return Result;
    }

    // Build request body
    TSharedPtr<FJsonObject> RequestJson = MakeShareable(new FJsonObject);
    RequestJson->SetStringField(TEXT("license_key"), LicenseKey);
    RequestJson->SetStringField(TEXT("device_identifier"), GetDeviceId());
    RequestJson->SetStringField(TEXT("hostname"), FPlatformProcess::ComputerName());

    FString RequestBody;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&RequestBody);
    FJsonSerializer::Serialize(RequestJson.ToSharedRef(), Writer);

    // Make synchronous request
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(CurrentConfig.ApiUrl + TEXT("/licenses/activate"));
    Request->SetVerb(TEXT("POST"));
    Request->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    Request->SetHeader(TEXT("Authorization"), FString::Printf(TEXT("Bearer %s"), *CurrentConfig.ApiKey));
    Request->SetContentAsString(RequestBody);

    Request->ProcessRequest();

    double StartTime = FPlatformTime::Seconds();
    while (Request->GetStatus() == EHttpRequestStatus::Processing)
    {
        FPlatformProcess::Sleep(0.01f);
        if (FPlatformTime::Seconds() - StartTime > 30.0)
        {
            Result.ErrorMessage = TEXT("Request timeout");
            return Result;
        }
    }

    if (Request->GetStatus() == EHttpRequestStatus::Succeeded)
    {
        FString Response = Request->GetResponse()->GetContentAsString();

        TSharedPtr<FJsonObject> JsonResponse;
        TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response);
        if (FJsonSerializer::Deserialize(Reader, JsonResponse) && JsonResponse.IsValid())
        {
            if (JsonResponse->HasField(TEXT("id")))
            {
                Result.bSuccess = true;
                Result.ActivationId = JsonResponse->GetStringField(TEXT("id"));
            }
            else if (JsonResponse->HasField(TEXT("error")))
            {
                Result.ErrorMessage = JsonResponse->GetStringField(TEXT("message"));
            }
        }
    }
    else
    {
        Result.ErrorMessage = TEXT("Network error");
    }

    return Result;
}

bool ULicenseSeatSubsystem::Deactivate(const FString& LicenseKey)
{
    if (!bIsInitialized)
    {
        return false;
    }

    // Build request body
    TSharedPtr<FJsonObject> RequestJson = MakeShareable(new FJsonObject);
    RequestJson->SetStringField(TEXT("license_key"), LicenseKey);
    RequestJson->SetStringField(TEXT("device_identifier"), GetDeviceId());

    FString RequestBody;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&RequestBody);
    FJsonSerializer::Serialize(RequestJson.ToSharedRef(), Writer);

    // Make synchronous request
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(CurrentConfig.ApiUrl + TEXT("/licenses/deactivate"));
    Request->SetVerb(TEXT("POST"));
    Request->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    Request->SetHeader(TEXT("Authorization"), FString::Printf(TEXT("Bearer %s"), *CurrentConfig.ApiKey));
    Request->SetContentAsString(RequestBody);

    Request->ProcessRequest();

    double StartTime = FPlatformTime::Seconds();
    while (Request->GetStatus() == EHttpRequestStatus::Processing)
    {
        FPlatformProcess::Sleep(0.01f);
        if (FPlatformTime::Seconds() - StartTime > 30.0)
        {
            return false;
        }
    }

    return Request->GetStatus() == EHttpRequestStatus::Succeeded &&
           Request->GetResponse()->GetResponseCode() == 200;
}

void ULicenseSeatSubsystem::ValidateAsync(const FString& LicenseKey, FOnValidationComplete Callback)
{
    if (!bIsInitialized)
    {
        FLicenseValidationResult Result;
        Result.bValid = false;
        Result.Reason = TEXT("LicenseSeat not initialized");
        Callback.ExecuteIfBound(Result);
        return;
    }

    // Build request body
    TSharedPtr<FJsonObject> RequestJson = MakeShareable(new FJsonObject);
    RequestJson->SetStringField(TEXT("license_key"), LicenseKey);
    RequestJson->SetStringField(TEXT("device_identifier"), GetDeviceId());
    if (!CurrentConfig.ProductSlug.IsEmpty())
    {
        RequestJson->SetStringField(TEXT("product_slug"), CurrentConfig.ProductSlug);
    }

    FString RequestBody;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&RequestBody);
    FJsonSerializer::Serialize(RequestJson.ToSharedRef(), Writer);

    MakeApiRequest(CurrentConfig.ApiUrl + TEXT("/licenses/validate"), RequestBody,
        [this, LicenseKey, Callback](bool bSuccess, const FString& Response)
        {
            FLicenseValidationResult Result;
            Result.LicenseKey = LicenseKey;

            if (bSuccess)
            {
                Result = ParseValidationResponse(Response);
            }
            else
            {
                Result.bValid = false;
                Result.Reason = TEXT("Network error");
            }

            CurrentStatus = Result;
            OnLicenseStatusChanged.Broadcast(Result);
            Callback.ExecuteIfBound(Result);
        });
}

void ULicenseSeatSubsystem::ActivateAsync(const FString& LicenseKey, FOnActivationComplete Callback)
{
    if (!bIsInitialized)
    {
        FLicenseActivationResult Result;
        Result.bSuccess = false;
        Result.ErrorMessage = TEXT("LicenseSeat not initialized");
        Callback.ExecuteIfBound(Result);
        return;
    }

    // Build request body
    TSharedPtr<FJsonObject> RequestJson = MakeShareable(new FJsonObject);
    RequestJson->SetStringField(TEXT("license_key"), LicenseKey);
    RequestJson->SetStringField(TEXT("device_identifier"), GetDeviceId());
    RequestJson->SetStringField(TEXT("hostname"), FPlatformProcess::ComputerName());

    FString RequestBody;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&RequestBody);
    FJsonSerializer::Serialize(RequestJson.ToSharedRef(), Writer);

    MakeApiRequest(CurrentConfig.ApiUrl + TEXT("/licenses/activate"), RequestBody,
        [this, Callback](bool bSuccess, const FString& Response)
        {
            FLicenseActivationResult Result;
            Result.bSuccess = false;
            Result.DeviceId = GetDeviceId();

            if (bSuccess)
            {
                TSharedPtr<FJsonObject> JsonResponse;
                TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response);
                if (FJsonSerializer::Deserialize(Reader, JsonResponse) && JsonResponse.IsValid())
                {
                    if (JsonResponse->HasField(TEXT("id")))
                    {
                        Result.bSuccess = true;
                        Result.ActivationId = JsonResponse->GetStringField(TEXT("id"));
                    }
                    else if (JsonResponse->HasField(TEXT("error")))
                    {
                        Result.ErrorMessage = JsonResponse->GetStringField(TEXT("message"));
                    }
                }
            }
            else
            {
                Result.ErrorMessage = TEXT("Network error");
            }

            Callback.ExecuteIfBound(Result);
        });
}

FLicenseValidationResult ULicenseSeatSubsystem::GetStatus() const
{
    return CurrentStatus;
}

bool ULicenseSeatSubsystem::IsLicenseValid() const
{
    return CurrentStatus.bValid;
}

FString ULicenseSeatSubsystem::GetDeviceId() const
{
    return GenerateDeviceId();
}

void ULicenseSeatSubsystem::StartAutoValidation(const FString& LicenseKey)
{
    AutoValidationLicenseKey = LicenseKey;

    if (CurrentConfig.AutoValidateInterval > 0)
    {
        GetWorld()->GetTimerManager().SetTimer(
            AutoValidationTimerHandle,
            this,
            &ULicenseSeatSubsystem::OnAutoValidationTimer,
            CurrentConfig.AutoValidateInterval,
            true);

        // Run immediately
        OnAutoValidationTimer();
    }
}

void ULicenseSeatSubsystem::StopAutoValidation()
{
    if (AutoValidationTimerHandle.IsValid())
    {
        GetWorld()->GetTimerManager().ClearTimer(AutoValidationTimerHandle);
        AutoValidationTimerHandle.Invalidate();
    }
    AutoValidationLicenseKey.Empty();
}

bool ULicenseSeatSubsystem::IsAutoValidationRunning() const
{
    return AutoValidationTimerHandle.IsValid();
}

FString ULicenseSeatSubsystem::GenerateDeviceId() const
{
    // Get platform-specific machine ID
    FString MachineId;

#if PLATFORM_WINDOWS
    // Windows: Use MachineGuid from registry
    MachineId = FPlatformMisc::GetMachineId().ToString();
#elif PLATFORM_MAC
    // macOS: Use hardware UUID
    MachineId = FPlatformMisc::GetMachineId().ToString();
#else
    // Linux/Other: Use login ID + hostname
    MachineId = FPlatformMisc::GetLoginId() + TEXT("@") + FPlatformProcess::ComputerName();
#endif

    // Hash with SHA256 for consistent length
    std::string Input = TCHAR_TO_UTF8(*MachineId);
    std::string HashHex;
    picosha2::hash256_hex_string(Input, HashHex);

    // Return first 32 characters
    return FString(UTF8_TO_TCHAR(HashHex.substr(0, 32).c_str()));
}

void ULicenseSeatSubsystem::MakeApiRequest(const FString& Endpoint, const FString& Body,
    TFunction<void(bool bSuccess, const FString& Response)> Callback)
{
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(Endpoint);
    Request->SetVerb(TEXT("POST"));
    Request->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    Request->SetHeader(TEXT("Authorization"), FString::Printf(TEXT("Bearer %s"), *CurrentConfig.ApiKey));
    Request->SetContentAsString(Body);

    Request->OnProcessRequestComplete().BindLambda(
        [Callback](FHttpRequestPtr Request, FHttpResponsePtr Response, bool bConnectedSuccessfully)
        {
            if (bConnectedSuccessfully && Response.IsValid())
            {
                Callback(true, Response->GetContentAsString());
            }
            else
            {
                Callback(false, TEXT(""));
            }
        });

    Request->ProcessRequest();
}

FLicenseValidationResult ULicenseSeatSubsystem::ParseValidationResponse(const FString& Response)
{
    FLicenseValidationResult Result;
    Result.bValid = false;

    TSharedPtr<FJsonObject> JsonResponse;
    TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response);

    if (!FJsonSerializer::Deserialize(Reader, JsonResponse) || !JsonResponse.IsValid())
    {
        Result.Reason = TEXT("Invalid JSON response");
        return Result;
    }

    // Check for error response
    if (JsonResponse->HasField(TEXT("error")))
    {
        Result.Reason = JsonResponse->GetStringField(TEXT("message"));
        return Result;
    }

    // Parse validation result
    Result.bValid = JsonResponse->GetBoolField(TEXT("valid"));

    if (!Result.bValid && JsonResponse->HasField(TEXT("reason")))
    {
        Result.Reason = JsonResponse->GetStringField(TEXT("reason"));
    }

    // Parse license info
    if (JsonResponse->HasField(TEXT("license")))
    {
        TSharedPtr<FJsonObject> LicenseJson = JsonResponse->GetObjectField(TEXT("license"));
        if (LicenseJson.IsValid())
        {
            Result.LicenseKey = LicenseJson->GetStringField(TEXT("key"));

            FString StatusStr = LicenseJson->GetStringField(TEXT("status"));
            if (StatusStr == TEXT("active"))
                Result.Status = ELicenseStatus::Active;
            else if (StatusStr == TEXT("expired"))
                Result.Status = ELicenseStatus::Expired;
            else if (StatusStr == TEXT("revoked"))
                Result.Status = ELicenseStatus::Revoked;
            else if (StatusStr == TEXT("suspended"))
                Result.Status = ELicenseStatus::Suspended;
            else if (StatusStr == TEXT("pending"))
                Result.Status = ELicenseStatus::Pending;

            // Parse expiration
            if (LicenseJson->HasField(TEXT("expires_at")) &&
                !LicenseJson->GetStringField(TEXT("expires_at")).IsEmpty())
            {
                Result.bHasExpiration = true;
                FDateTime::ParseIso8601(*LicenseJson->GetStringField(TEXT("expires_at")), Result.ExpiresAt);
            }
        }
    }

    return Result;
}

void ULicenseSeatSubsystem::OnAutoValidationTimer()
{
    if (!AutoValidationLicenseKey.IsEmpty())
    {
        ValidateAsync(AutoValidationLicenseKey, FOnValidationComplete());
    }
}
