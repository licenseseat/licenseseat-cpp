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
// Use UE's third-party include guards to suppress warnings
THIRD_PARTY_INCLUDES_START
extern "C" {
#include "ed25519.h"
}
#include "picosha2.h"
THIRD_PARTY_INCLUDES_END

namespace {

FString BuildLicenseEndpoint(const FLicenseSeatConfig& Config, const FString& LicenseKey,
                             const TCHAR* Action)
{
    return Config.ApiUrl + TEXT("/products/") + Config.ProductSlug + TEXT("/licenses/") +
           LicenseKey + TEXT("/") + Action;
}

TSharedPtr<FJsonObject> BuildDevicePayload(const FString& Fingerprint, const FString& DeviceName)
{
    TSharedPtr<FJsonObject> RequestJson = MakeShareable(new FJsonObject);
    RequestJson->SetStringField(TEXT("fingerprint"), Fingerprint);
    RequestJson->SetStringField(TEXT("device_id"), Fingerprint);

    TSharedPtr<FJsonObject> ComponentsJson = MakeShareable(new FJsonObject);
    ComponentsJson->SetStringField(TEXT("schema_version"), TEXT("1"));
    ComponentsJson->SetStringField(TEXT("sdk"), TEXT("unreal-plugin"));
    ComponentsJson->SetStringField(TEXT("platform"), FPlatformProperties::PlatformName());
    ComponentsJson->SetStringField(TEXT("hostname"), FPlatformProcess::ComputerName());
    RequestJson->SetObjectField(TEXT("fingerprint_components"), ComponentsJson);

    if (!DeviceName.IsEmpty())
    {
        RequestJson->SetStringField(TEXT("device_name"), DeviceName);
    }

    return RequestJson;
}

FString ToJsonString(const TSharedPtr<FJsonObject>& Json)
{
    FString RequestBody;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&RequestBody);
    FJsonSerializer::Serialize(Json.ToSharedRef(), Writer);
    return RequestBody;
}

FString ExtractErrorMessage(const TSharedPtr<FJsonObject>& JsonResponse)
{
    if (!JsonResponse.IsValid())
    {
        return TEXT("Request failed");
    }

    const TArray<TSharedPtr<FJsonValue>>* Errors = nullptr;
    if (JsonResponse->TryGetArrayField(TEXT("errors"), Errors) && Errors != nullptr &&
        Errors->Num() > 0)
    {
        TSharedPtr<FJsonObject> ErrorObject;
        if ((*Errors)[0]->TryGetObject(ErrorObject) && ErrorObject.IsValid())
        {
            FString Message;
            if (ErrorObject->TryGetStringField(TEXT("detail"), Message))
            {
                return Message;
            }
            if (ErrorObject->TryGetStringField(TEXT("message"), Message))
            {
                return Message;
            }
            if (ErrorObject->TryGetStringField(TEXT("title"), Message))
            {
                return Message;
            }
        }
    }

    const TSharedPtr<FJsonObject>* ErrorObject = nullptr;
    if (JsonResponse->TryGetObjectField(TEXT("error"), ErrorObject) && ErrorObject != nullptr &&
        ErrorObject->IsValid())
    {
        FString Message;
        if ((*ErrorObject)->TryGetStringField(TEXT("message"), Message))
        {
            return Message;
        }
    }

    FString Message;
    if (JsonResponse->TryGetStringField(TEXT("message"), Message))
    {
        return Message;
    }

    return TEXT("Request failed");
}

ELicenseStatus ParseLicenseStatus(const FString& StatusStr)
{
    if (StatusStr == TEXT("active"))
        return ELicenseStatus::Active;
    if (StatusStr == TEXT("expired"))
        return ELicenseStatus::Expired;
    if (StatusStr == TEXT("revoked"))
        return ELicenseStatus::Revoked;
    if (StatusStr == TEXT("suspended"))
        return ELicenseStatus::Suspended;
    if (StatusStr == TEXT("pending"))
        return ELicenseStatus::Pending;
    return ELicenseStatus::Unknown;
}

FString JsonFieldToString(const TSharedPtr<FJsonObject>& JsonObject, const FString& FieldName)
{
    FString StringValue;
    if (JsonObject->TryGetStringField(FieldName, StringValue))
    {
        return StringValue;
    }

    double NumberValue = 0.0;
    if (JsonObject->TryGetNumberField(FieldName, NumberValue))
    {
        return LexToString(static_cast<int64>(NumberValue));
    }

    return FString();
}

}  // namespace

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

    const FString RequestBody = ToJsonString(BuildDevicePayload(GetDeviceId(), TEXT("")));

    // Make synchronous request (blocking - use with caution)
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(BuildLicenseEndpoint(CurrentConfig, LicenseKey, TEXT("validate")));
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

    if (Request->GetStatus() == EHttpRequestStatus::Succeeded && Request->GetResponse().IsValid())
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

    const FString RequestBody =
        ToJsonString(BuildDevicePayload(GetDeviceId(), FPlatformProcess::ComputerName()));

    // Make synchronous request
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(BuildLicenseEndpoint(CurrentConfig, LicenseKey, TEXT("activate")));
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

    if (Request->GetStatus() == EHttpRequestStatus::Succeeded && Request->GetResponse().IsValid())
    {
        FString Response = Request->GetResponse()->GetContentAsString();

        TSharedPtr<FJsonObject> JsonResponse;
        TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response);
        if (FJsonSerializer::Deserialize(Reader, JsonResponse) && JsonResponse.IsValid())
        {
            if (JsonResponse->HasField(TEXT("id")))
            {
                Result.bSuccess = true;
                Result.ActivationId = JsonFieldToString(JsonResponse, TEXT("id"));
            }
            else
            {
                Result.ErrorMessage = ExtractErrorMessage(JsonResponse);
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

    const FString RequestBody = ToJsonString(BuildDevicePayload(GetDeviceId(), TEXT("")));

    // Make synchronous request
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(BuildLicenseEndpoint(CurrentConfig, LicenseKey, TEXT("deactivate")));
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
           Request->GetResponse().IsValid() &&
           Request->GetResponse()->GetResponseCode() >= 200 &&
           Request->GetResponse()->GetResponseCode() < 300;
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

    const FString RequestBody = ToJsonString(BuildDevicePayload(GetDeviceId(), TEXT("")));

    MakeApiRequest(BuildLicenseEndpoint(CurrentConfig, LicenseKey, TEXT("validate")), RequestBody,
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

    const FString RequestBody =
        ToJsonString(BuildDevicePayload(GetDeviceId(), FPlatformProcess::ComputerName()));

    MakeApiRequest(BuildLicenseEndpoint(CurrentConfig, LicenseKey, TEXT("activate")), RequestBody,
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
                        Result.ActivationId = JsonFieldToString(JsonResponse, TEXT("id"));
                    }
                    else
                    {
                        Result.ErrorMessage = ExtractErrorMessage(JsonResponse);
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
                const int32 StatusCode = Response->GetResponseCode();
                Callback(StatusCode >= 200 && StatusCode < 300, Response->GetContentAsString());
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

    if (JsonResponse->HasField(TEXT("error")) || JsonResponse->HasField(TEXT("errors")))
    {
        Result.Reason = ExtractErrorMessage(JsonResponse);
        return Result;
    }

    // Parse validation result
    Result.bValid = JsonResponse->GetBoolField(TEXT("valid"));

    if (JsonResponse->HasField(TEXT("message")))
    {
        Result.Reason = JsonResponse->GetStringField(TEXT("message"));
    }

    // Parse license info
    if (JsonResponse->HasField(TEXT("license")))
    {
        TSharedPtr<FJsonObject> LicenseJson = JsonResponse->GetObjectField(TEXT("license"));
        if (LicenseJson.IsValid())
        {
            Result.LicenseKey = LicenseJson->GetStringField(TEXT("key"));

            Result.Status = ParseLicenseStatus(LicenseJson->GetStringField(TEXT("status")));

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
