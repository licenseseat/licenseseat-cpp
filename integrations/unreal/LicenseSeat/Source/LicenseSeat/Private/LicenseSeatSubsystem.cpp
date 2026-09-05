// Copyright LicenseSeat. All Rights Reserved.

#include "LicenseSeatSubsystem.h"

#include "Dom/JsonObject.h"
#include "GenericPlatform/GenericPlatformHttp.h"
#include "HAL/PlatformMisc.h"
#include "HttpModule.h"
#include "Interfaces/IHttpRequest.h"
#include "Interfaces/IHttpResponse.h"
#include "Misc/Guid.h"
#include "Serialization/JsonReader.h"
#include "Serialization/JsonSerializer.h"
#include "TimerManager.h"
#include <cmath>

// PicoSHA2 is used only to retain the plugin's stable device fingerprint.
THIRD_PARTY_INCLUDES_START
#include "picosha2.h"
THIRD_PARTY_INCLUDES_END

namespace {

constexpr int32 MaxRequestBytes = 1024 * 1024;
constexpr int32 MaxApiKeyChars = 4096;
constexpr int32 MaxLicenseKeyChars = 512;
constexpr int32 MaxProductSlugChars = 100;
constexpr float MaxTimerIntervalSeconds = 366.0f * 24.0f * 60.0f * 60.0f;

bool IsSafeText(const FString& Value, int32 Maximum, bool bAllowEmpty = false) {
    if ((!bAllowEmpty && Value.IsEmpty()) || Value.Len() > Maximum) {
        return false;
    }
    for (const TCHAR Character : Value) {
        if (Character <= 0x1f || Character == 0x7f) {
            return false;
        }
    }
    return true;
}

bool IsSafeProductSlug(const FString& Value) {
    if (!IsSafeText(Value, MaxProductSlugChars)) {
        return false;
    }
    for (const TCHAR Character : Value) {
        if (!((Character >= TEXT('a') && Character <= TEXT('z')) ||
              (Character >= TEXT('A') && Character <= TEXT('Z')) ||
              (Character >= TEXT('0') && Character <= TEXT('9')) || Character == TEXT('-') ||
              Character == TEXT('_') || Character == TEXT('.'))) {
            return false;
        }
    }
    return true;
}

bool IsLoopbackAuthority(FString Authority) {
    Authority = Authority.ToLower();
    if (Authority.StartsWith(TEXT("[::1]"))) {
        return Authority == TEXT("[::1]") || Authority.StartsWith(TEXT("[::1]:"));
    }
    const int32 Colon = Authority.Find(TEXT(":"));
    const FString Host = Colon == INDEX_NONE ? Authority : Authority.Left(Colon);
    return Host == TEXT("localhost") || Host == TEXT("127.0.0.1");
}

bool IsValidApiUrl(const FLicenseSeatConfig& Config) {
    const FString& Url = Config.ApiUrl;
    if (!IsSafeText(Url, 2048) || Url.Contains(TEXT("\\")) || Url.Contains(TEXT("?")) ||
        Url.Contains(TEXT("#")) || Url.Contains(TEXT("@"))) {
        return false;
    }

    int32 SchemeLength = 0;
    bool bPlaintext = false;
    if (Url.StartsWith(TEXT("https://"), ESearchCase::CaseSensitive)) {
        SchemeLength = 8;
    } else if (Url.StartsWith(TEXT("http://"), ESearchCase::CaseSensitive)) {
        SchemeLength = 7;
        bPlaintext = true;
    } else {
        return false;
    }

    const int32 PathStart =
        Url.Find(TEXT("/"), ESearchCase::CaseSensitive, ESearchDir::FromStart, SchemeLength);
    const FString Authority = PathStart == INDEX_NONE
                                  ? Url.Mid(SchemeLength)
                                  : Url.Mid(SchemeLength, PathStart - SchemeLength);
    if (Authority.IsEmpty()) {
        return false;
    }
    return !bPlaintext || (Config.bAllowInsecureLoopback && IsLoopbackAuthority(Authority));
}

FString BuildLicenseEndpoint(const FLicenseSeatConfig& Config, const TCHAR* Action) {
    return Config.ApiUrl + TEXT("/products/") +
           FGenericPlatformHttp::UrlEncode(Config.ProductSlug) + TEXT("/licenses/") + Action;
}

TSharedPtr<FJsonObject> BuildDevicePayload(const FString& Fingerprint, const FString& DeviceName,
                                           const FString& LicenseKey) {
    TSharedPtr<FJsonObject> RequestJson = MakeShareable(new FJsonObject);
    RequestJson->SetStringField(TEXT("license_key"), LicenseKey);
    RequestJson->SetStringField(TEXT("fingerprint"), Fingerprint);
    RequestJson->SetStringField(TEXT("device_id"), Fingerprint);

    TSharedPtr<FJsonObject> ComponentsJson = MakeShareable(new FJsonObject);
    ComponentsJson->SetStringField(TEXT("schema_version"), TEXT("1"));
    ComponentsJson->SetStringField(TEXT("sdk"), TEXT("unreal-plugin"));
    ComponentsJson->SetStringField(TEXT("platform"), FPlatformProperties::PlatformName());
    ComponentsJson->SetStringField(TEXT("hostname"), FPlatformProcess::ComputerName());
    RequestJson->SetObjectField(TEXT("fingerprint_components"), ComponentsJson);

    if (!DeviceName.IsEmpty()) {
        RequestJson->SetStringField(TEXT("device_name"), DeviceName);
    }

    return RequestJson;
}

FString ToJsonString(const TSharedPtr<FJsonObject>& Json) {
    FString RequestBody;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&RequestBody);
    FJsonSerializer::Serialize(Json.ToSharedRef(), Writer);
    return RequestBody;
}

// Hosted UUIDs and integer-primary-key engines share the same identifier contract.
bool TryGetIdentifierField(const TSharedPtr<FJsonObject>& JsonResponse, const TCHAR* FieldName,
                           FString& OutValue) {
    const TSharedPtr<FJsonValue> Field = JsonResponse->TryGetField(FieldName);
    if (!Field.IsValid()) return false;
    if (Field->Type == EJson::String)
        return Field->TryGetString(OutValue) && IsSafeText(OutValue, 255) &&
               !OutValue.Contains(TEXT(" "));
    double NumericValue = 0.0;
    // Unreal stores JSON numbers as doubles. Reject values outside its exact
    // integer range instead of rounding or invoking an out-of-range cast.
    if (Field->Type == EJson::Number && Field->TryGetNumber(NumericValue) &&
        std::isfinite(NumericValue) && NumericValue > 0.0 &&
        NumericValue <= 9007199254740991.0 && std::floor(NumericValue) == NumericValue) {
        OutValue = LexToString(static_cast<int64>(NumericValue));
        return true;
    }
    return false;
}

FString ExtractErrorMessage(const TSharedPtr<FJsonObject>& JsonResponse) {
    if (!JsonResponse.IsValid()) {
        return TEXT("Request failed");
    }

    const TArray<TSharedPtr<FJsonValue>>* Errors = nullptr;
    if (JsonResponse->TryGetArrayField(TEXT("errors"), Errors) && Errors != nullptr &&
        Errors->Num() > 0) {
        TSharedPtr<FJsonObject> ErrorObject;
        if ((*Errors)[0]->TryGetObject(ErrorObject) && ErrorObject.IsValid()) {
            FString Message;
            if (ErrorObject->TryGetStringField(TEXT("detail"), Message)) {
                return Message;
            }
            if (ErrorObject->TryGetStringField(TEXT("message"), Message)) {
                return Message;
            }
            if (ErrorObject->TryGetStringField(TEXT("title"), Message)) {
                return Message;
            }
        }
    }

    const TSharedPtr<FJsonObject>* ErrorObject = nullptr;
    if (JsonResponse->TryGetObjectField(TEXT("error"), ErrorObject) && ErrorObject != nullptr &&
        ErrorObject->IsValid()) {
        FString Message;
        if ((*ErrorObject)->TryGetStringField(TEXT("message"), Message)) {
            return Message;
        }
    }

    FString Message;
    if (JsonResponse->TryGetStringField(TEXT("message"), Message)) {
        return Message;
    }

    return TEXT("Request failed");
}

ELicenseStatus ParseLicenseStatus(const FString& StatusStr) {
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

bool IsBoundedJsonResponse(const FHttpResponsePtr& Response, int32 MaximumBytes) {
    if (!Response.IsValid() || Response->GetContent().Num() > MaximumBytes ||
        Response->GetEffectiveURL() != Response->GetURL()) {
        return false;
    }
    const FString ContentType = Response->GetHeader(TEXT("Content-Type"));
    return ContentType.StartsWith(TEXT("application/json"), ESearchCase::IgnoreCase);
}

bool ParseActivationResponse(const FString& Response, const FString& ExpectedLicenseKey,
                             const FString& ExpectedFingerprint, FLicenseActivationResult& Result) {
    TSharedPtr<FJsonObject> JsonResponse;
    const TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response);
    if (!FJsonSerializer::Deserialize(Reader, JsonResponse) || !JsonResponse.IsValid()) {
        Result.ErrorMessage = TEXT("Invalid JSON response");
        return false;
    }

    FString Object;
    FString LicenseKey;
    FString Fingerprint;
    FString ActivatedAt;
    FString ActivationId;
    if (!JsonResponse->TryGetStringField(TEXT("object"), Object) || Object != TEXT("activation") ||
        !TryGetIdentifierField(JsonResponse, TEXT("id"), ActivationId) ||
        !JsonResponse->TryGetStringField(TEXT("license_key"), LicenseKey) ||
        LicenseKey != ExpectedLicenseKey ||
        !(JsonResponse->TryGetStringField(TEXT("fingerprint"), Fingerprint) ||
          JsonResponse->TryGetStringField(TEXT("device_id"), Fingerprint)) ||
        Fingerprint != ExpectedFingerprint ||
        !JsonResponse->TryGetStringField(TEXT("activated_at"), ActivatedAt)) {
        Result.ErrorMessage = ExtractErrorMessage(JsonResponse);
        if (Result.ErrorMessage == TEXT("Request failed")) {
            Result.ErrorMessage = TEXT("Activation response identity is invalid");
        }
        return false;
    }

    FDateTime ParsedActivationTime;
    if (!FDateTime::ParseIso8601(*ActivatedAt, ParsedActivationTime)) {
        Result.ErrorMessage = TEXT("Activation response timestamp is invalid");
        return false;
    }

    Result.bSuccess = true;
    Result.ActivationId = ActivationId;
    Result.DeviceId = ExpectedFingerprint;
    return true;
}

bool ParseDeactivationResponse(const FString& Response) {
    TSharedPtr<FJsonObject> JsonResponse;
    const TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response);
    if (!FJsonSerializer::Deserialize(Reader, JsonResponse) || !JsonResponse.IsValid()) {
        return false;
    }
    FString Object;
    FString DeactivatedAt;
    FString ActivationId;
    FDateTime Parsed;
    return JsonResponse->TryGetStringField(TEXT("object"), Object) &&
           Object == TEXT("deactivation") &&
           TryGetIdentifierField(JsonResponse, TEXT("activation_id"), ActivationId) &&
           JsonResponse->TryGetStringField(TEXT("deactivated_at"), DeactivatedAt) &&
           FDateTime::ParseIso8601(*DeactivatedAt, Parsed);
}

} // namespace

void ULicenseSeatSubsystem::Initialize(FSubsystemCollectionBase& Collection) {
    Super::Initialize(Collection);
    CachedDeviceId = GenerateDeviceId();
    UE_LOG(LogTemp, Log, TEXT("LicenseSeat: Subsystem initialized"));
}

void ULicenseSeatSubsystem::Deinitialize() {
    bIsInitialized = false;
    StopAutoValidation();
    CurrentConfig.ApiKey.Empty();
    AutoValidationLicenseKey.Empty();
    Super::Deinitialize();
    UE_LOG(LogTemp, Log, TEXT("LicenseSeat: Subsystem deinitialized"));
}

void ULicenseSeatSubsystem::InitializeWithConfig(const FLicenseSeatConfig& Config) {
    StopAutoValidation();
    CurrentConfig = Config;
    while (CurrentConfig.ApiUrl.EndsWith(TEXT("/"))) {
        CurrentConfig.ApiUrl.LeftChopInline(1, EAllowShrinking::No);
    }
    if (!IsSafeText(CurrentConfig.ApiKey, MaxApiKeyChars) ||
        !IsSafeProductSlug(CurrentConfig.ProductSlug) || !IsValidApiUrl(CurrentConfig) ||
        !FMath::IsFinite(CurrentConfig.RequestTimeoutSeconds) ||
        CurrentConfig.RequestTimeoutSeconds < 1.0f ||
        CurrentConfig.RequestTimeoutSeconds > 300.0f || CurrentConfig.MaxResponseBytes < 1 ||
        CurrentConfig.MaxResponseBytes > 16 * 1024 * 1024 ||
        !FMath::IsFinite(CurrentConfig.AutoValidateInterval) ||
        CurrentConfig.AutoValidateInterval < 0.0f ||
        CurrentConfig.AutoValidateInterval > MaxTimerIntervalSeconds) {
        bIsInitialized = false;
        CurrentConfig.ApiKey.Empty();
        UE_LOG(LogTemp, Error, TEXT("LicenseSeat: Refusing invalid or insecure configuration"));
        return;
    }

    if (CachedDeviceId.IsEmpty()) {
        CachedDeviceId = GenerateDeviceId();
    }
    bIsInitialized = true;
    UE_LOG(LogTemp, Log, TEXT("LicenseSeat: Configured with product: %s"), *Config.ProductSlug);
}

FLicenseValidationResult ULicenseSeatSubsystem::Validate(const FString& LicenseKey) {
    // For synchronous API, we'll use a blocking approach
    // This is not ideal for game threads - prefer ValidateAsync
    FLicenseValidationResult Result;
    Result.bValid = false;
    Result.LicenseKey = LicenseKey;

    if (!bIsInitialized || !IsSafeText(LicenseKey, MaxLicenseKeyChars)) {
        Result.Reason =
            bIsInitialized ? TEXT("License key is invalid") : TEXT("LicenseSeat not initialized");
        return Result;
    }

    const FString RequestBody =
        ToJsonString(BuildDevicePayload(GetDeviceId(), TEXT(""), LicenseKey));
    if (FTCHARToUTF8(*RequestBody).Length() > MaxRequestBytes) {
        Result.Reason = TEXT("Request is too large");
        return Result;
    }

    // Make synchronous request (blocking - use with caution)
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(BuildLicenseEndpoint(CurrentConfig, TEXT("validate")));
    Request->SetVerb(TEXT("POST"));
    Request->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    Request->SetHeader(TEXT("Accept"), TEXT("application/json"));
    Request->SetHeader(TEXT("Accept-Encoding"), TEXT("identity"));
    Request->SetHeader(TEXT("Authorization"),
                       FString::Printf(TEXT("Bearer %s"), *CurrentConfig.ApiKey));
    Request->SetContentAsString(RequestBody);
    Request->SetTimeout(CurrentConfig.RequestTimeoutSeconds);

    // Process request synchronously
    Request->ProcessRequest();

    // Wait for completion (blocks!)
    double StartTime = FPlatformTime::Seconds();
    while (Request->GetStatus() == EHttpRequestStatus::Processing) {
        FPlatformProcess::Sleep(0.01f);
        if (FPlatformTime::Seconds() - StartTime > CurrentConfig.RequestTimeoutSeconds) {
            Request->CancelRequest();
            Result.Reason = TEXT("Request timeout");
            return Result;
        }
    }

    const FHttpResponsePtr ResponseObject = Request->GetResponse();
    if (Request->GetStatus() == EHttpRequestStatus::Succeeded &&
        IsBoundedJsonResponse(ResponseObject, CurrentConfig.MaxResponseBytes) &&
        ResponseObject->GetResponseCode() >= 200 && ResponseObject->GetResponseCode() < 300) {
        Result = ParseValidationResponse(ResponseObject->GetContentAsString(), LicenseKey);
    } else {
        Result.Reason = TEXT("Network error");
    }

    CurrentStatus = Result;
    return Result;
}

FLicenseActivationResult ULicenseSeatSubsystem::Activate(const FString& LicenseKey) {
    FLicenseActivationResult Result;
    Result.bSuccess = false;
    Result.DeviceId = GetDeviceId();

    if (!bIsInitialized || !IsSafeText(LicenseKey, MaxLicenseKeyChars)) {
        Result.ErrorMessage =
            bIsInitialized ? TEXT("License key is invalid") : TEXT("LicenseSeat not initialized");
        return Result;
    }

    const FString RequestBody = ToJsonString(
        BuildDevicePayload(GetDeviceId(), FPlatformProcess::ComputerName(), LicenseKey));
    if (FTCHARToUTF8(*RequestBody).Length() > MaxRequestBytes) {
        Result.ErrorMessage = TEXT("Request is too large");
        return Result;
    }

    // Make synchronous request
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(BuildLicenseEndpoint(CurrentConfig, TEXT("activate")));
    Request->SetVerb(TEXT("POST"));
    Request->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    Request->SetHeader(TEXT("Accept"), TEXT("application/json"));
    Request->SetHeader(TEXT("Accept-Encoding"), TEXT("identity"));
    Request->SetHeader(TEXT("Authorization"),
                       FString::Printf(TEXT("Bearer %s"), *CurrentConfig.ApiKey));
    Request->SetContentAsString(RequestBody);
    Request->SetTimeout(CurrentConfig.RequestTimeoutSeconds);

    Request->ProcessRequest();

    double StartTime = FPlatformTime::Seconds();
    while (Request->GetStatus() == EHttpRequestStatus::Processing) {
        FPlatformProcess::Sleep(0.01f);
        if (FPlatformTime::Seconds() - StartTime > CurrentConfig.RequestTimeoutSeconds) {
            Request->CancelRequest();
            Result.ErrorMessage = TEXT("Request timeout");
            return Result;
        }
    }

    const FHttpResponsePtr ResponseObject = Request->GetResponse();
    if (Request->GetStatus() == EHttpRequestStatus::Succeeded &&
        IsBoundedJsonResponse(ResponseObject, CurrentConfig.MaxResponseBytes) &&
        ResponseObject->GetResponseCode() >= 200 && ResponseObject->GetResponseCode() < 300) {
        ParseActivationResponse(ResponseObject->GetContentAsString(), LicenseKey, GetDeviceId(),
                                Result);
    } else {
        Result.ErrorMessage = TEXT("Network error");
    }

    return Result;
}

bool ULicenseSeatSubsystem::Deactivate(const FString& LicenseKey) {
    if (!bIsInitialized || !IsSafeText(LicenseKey, MaxLicenseKeyChars)) {
        return false;
    }

    const FString RequestBody =
        ToJsonString(BuildDevicePayload(GetDeviceId(), TEXT(""), LicenseKey));
    if (FTCHARToUTF8(*RequestBody).Length() > MaxRequestBytes) {
        return false;
    }

    // Make synchronous request
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(BuildLicenseEndpoint(CurrentConfig, TEXT("deactivate")));
    Request->SetVerb(TEXT("POST"));
    Request->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    Request->SetHeader(TEXT("Accept"), TEXT("application/json"));
    Request->SetHeader(TEXT("Accept-Encoding"), TEXT("identity"));
    Request->SetHeader(TEXT("Authorization"),
                       FString::Printf(TEXT("Bearer %s"), *CurrentConfig.ApiKey));
    Request->SetContentAsString(RequestBody);
    Request->SetTimeout(CurrentConfig.RequestTimeoutSeconds);

    Request->ProcessRequest();

    double StartTime = FPlatformTime::Seconds();
    while (Request->GetStatus() == EHttpRequestStatus::Processing) {
        FPlatformProcess::Sleep(0.01f);
        if (FPlatformTime::Seconds() - StartTime > CurrentConfig.RequestTimeoutSeconds) {
            Request->CancelRequest();
            return false;
        }
    }

    const FHttpResponsePtr ResponseObject = Request->GetResponse();
    return Request->GetStatus() == EHttpRequestStatus::Succeeded &&
           IsBoundedJsonResponse(ResponseObject, CurrentConfig.MaxResponseBytes) &&
           ResponseObject->GetResponseCode() >= 200 && ResponseObject->GetResponseCode() < 300 &&
           ParseDeactivationResponse(ResponseObject->GetContentAsString());
}

void ULicenseSeatSubsystem::ValidateAsync(const FString& LicenseKey,
                                          FOnValidationComplete Callback) {
    if (!bIsInitialized || !IsSafeText(LicenseKey, MaxLicenseKeyChars)) {
        FLicenseValidationResult Result;
        Result.bValid = false;
        Result.Reason =
            bIsInitialized ? TEXT("License key is invalid") : TEXT("LicenseSeat not initialized");
        Callback.ExecuteIfBound(Result);
        return;
    }

    const FString RequestBody =
        ToJsonString(BuildDevicePayload(GetDeviceId(), TEXT(""), LicenseKey));
    const TWeakObjectPtr<ULicenseSeatSubsystem> WeakThis(this);

    MakeApiRequest(BuildLicenseEndpoint(CurrentConfig, TEXT("validate")), RequestBody,
                   [WeakThis, LicenseKey, Callback](bool bSuccess, const FString& Response) {
                       ULicenseSeatSubsystem* Self = WeakThis.Get();
                       if (Self == nullptr || !Self->bIsInitialized) {
                           return;
                       }
                       FLicenseValidationResult Result;
                       Result.LicenseKey = LicenseKey;

                       if (bSuccess) {
                           Result = Self->ParseValidationResponse(Response, LicenseKey);
                       } else {
                           Result.bValid = false;
                           TSharedPtr<FJsonObject> ErrorJson;
                           const TSharedRef<TJsonReader<>> Reader =
                               TJsonReaderFactory<>::Create(Response);
                           Result.Reason = FJsonSerializer::Deserialize(Reader, ErrorJson)
                                               ? ExtractErrorMessage(ErrorJson)
                                               : TEXT("Network error");
                       }

                       Self->CurrentStatus = Result;
                       Self->OnLicenseStatusChanged.Broadcast(Result);
                       Callback.ExecuteIfBound(Result);
                   });
}

void ULicenseSeatSubsystem::ActivateAsync(const FString& LicenseKey,
                                          FOnActivationComplete Callback) {
    if (!bIsInitialized || !IsSafeText(LicenseKey, MaxLicenseKeyChars)) {
        FLicenseActivationResult Result;
        Result.bSuccess = false;
        Result.ErrorMessage =
            bIsInitialized ? TEXT("License key is invalid") : TEXT("LicenseSeat not initialized");
        Callback.ExecuteIfBound(Result);
        return;
    }

    const FString RequestBody = ToJsonString(
        BuildDevicePayload(GetDeviceId(), FPlatformProcess::ComputerName(), LicenseKey));
    const TWeakObjectPtr<ULicenseSeatSubsystem> WeakThis(this);

    MakeApiRequest(
        BuildLicenseEndpoint(CurrentConfig, TEXT("activate")), RequestBody,
        [WeakThis, LicenseKey, Callback](bool bSuccess, const FString& Response) {
            ULicenseSeatSubsystem* Self = WeakThis.Get();
            if (Self == nullptr || !Self->bIsInitialized) {
                return;
            }
            FLicenseActivationResult Result;
            Result.bSuccess = false;
            Result.DeviceId = Self->GetDeviceId();

            if (bSuccess) {
                ParseActivationResponse(Response, LicenseKey, Self->GetDeviceId(), Result);
            } else {
                TSharedPtr<FJsonObject> ErrorJson;
                const TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response);
                Result.ErrorMessage = FJsonSerializer::Deserialize(Reader, ErrorJson)
                                          ? ExtractErrorMessage(ErrorJson)
                                          : TEXT("Network error");
            }

            Callback.ExecuteIfBound(Result);
        });
}

FLicenseValidationResult ULicenseSeatSubsystem::GetStatus() const {
    return CurrentStatus;
}

bool ULicenseSeatSubsystem::IsLicenseValid() const {
    return CurrentStatus.bValid;
}

FString ULicenseSeatSubsystem::GetDeviceId() const {
    return CachedDeviceId;
}

void ULicenseSeatSubsystem::StartAutoValidation(const FString& LicenseKey) {
    StopAutoValidation();
    if (!bIsInitialized || !IsSafeText(LicenseKey, MaxLicenseKeyChars) ||
        !FMath::IsFinite(CurrentConfig.AutoValidateInterval) ||
        CurrentConfig.AutoValidateInterval <= 0.0f ||
        CurrentConfig.AutoValidateInterval > MaxTimerIntervalSeconds || GetWorld() == nullptr) {
        return;
    }
    AutoValidationLicenseKey = LicenseKey;

    GetWorld()->GetTimerManager().SetTimer(AutoValidationTimerHandle, this,
                                           &ULicenseSeatSubsystem::OnAutoValidationTimer,
                                           CurrentConfig.AutoValidateInterval, true);

    // Run immediately
    OnAutoValidationTimer();
}

void ULicenseSeatSubsystem::StopAutoValidation() {
    if (AutoValidationTimerHandle.IsValid() && GetWorld() != nullptr) {
        GetWorld()->GetTimerManager().ClearTimer(AutoValidationTimerHandle);
        AutoValidationTimerHandle.Invalidate();
    }
    AutoValidationLicenseKey.Empty();
}

bool ULicenseSeatSubsystem::IsAutoValidationRunning() const {
    return AutoValidationTimerHandle.IsValid();
}

FString ULicenseSeatSubsystem::GenerateDeviceId() const {
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

void ULicenseSeatSubsystem::MakeApiRequest(
    const FString& Endpoint, const FString& Body,
    TFunction<void(bool bSuccess, const FString& Response)> Callback) {
    if (!bIsInitialized || !IsSafeText(Endpoint, 8192) ||
        FTCHARToUTF8(*Body).Length() > MaxRequestBytes) {
        Callback(false, TEXT(""));
        return;
    }
    FHttpModule& HttpModule = FHttpModule::Get();
    TSharedRef<IHttpRequest> Request = HttpModule.CreateRequest();

    Request->SetURL(Endpoint);
    Request->SetVerb(TEXT("POST"));
    Request->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    Request->SetHeader(TEXT("Accept"), TEXT("application/json"));
    Request->SetHeader(TEXT("Accept-Encoding"), TEXT("identity"));
    Request->SetHeader(TEXT("Authorization"),
                       FString::Printf(TEXT("Bearer %s"), *CurrentConfig.ApiKey));
    Request->SetContentAsString(Body);
    Request->SetTimeout(CurrentConfig.RequestTimeoutSeconds);

    const TWeakObjectPtr<ULicenseSeatSubsystem> WeakThis(this);

    Request->OnProcessRequestComplete().BindLambda(
        [WeakThis, Callback](FHttpRequestPtr Request, FHttpResponsePtr Response,
                             bool bConnectedSuccessfully) {
            const ULicenseSeatSubsystem* Self = WeakThis.Get();
            if (Self == nullptr || !Self->bIsInitialized) {
                return;
            }
            if (bConnectedSuccessfully &&
                IsBoundedJsonResponse(Response, Self->CurrentConfig.MaxResponseBytes)) {
                const int32 StatusCode = Response->GetResponseCode();
                Callback(StatusCode >= 200 && StatusCode < 300, Response->GetContentAsString());
            } else {
                Callback(false, TEXT(""));
            }
        });

    if (!Request->ProcessRequest()) {
        Callback(false, TEXT(""));
    }
}

FLicenseValidationResult ULicenseSeatSubsystem::ParseValidationResponse(
    const FString& Response, const FString& ExpectedLicenseKey) {
    FLicenseValidationResult Result;
    Result.bValid = false;

    TSharedPtr<FJsonObject> JsonResponse;
    TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response);

    if (!FJsonSerializer::Deserialize(Reader, JsonResponse) || !JsonResponse.IsValid()) {
        Result.Reason = TEXT("Invalid JSON response");
        return Result;
    }

    if (JsonResponse->HasField(TEXT("error")) || JsonResponse->HasField(TEXT("errors"))) {
        Result.Reason = ExtractErrorMessage(JsonResponse);
        return Result;
    }

    FString Object;
    bool bServerValid = false;
    if (!JsonResponse->TryGetStringField(TEXT("object"), Object) ||
        Object != TEXT("validation_result") ||
        !JsonResponse->TryGetBoolField(TEXT("valid"), bServerValid)) {
        Result.Reason = TEXT("Validation response schema is invalid");
        return Result;
    }

    if (JsonResponse->HasField(TEXT("message"))) {
        JsonResponse->TryGetStringField(TEXT("message"), Result.Reason);
    }

    if (!bServerValid) {
        FString Code;
        if (!JsonResponse->TryGetStringField(TEXT("code"), Code) || !IsSafeText(Code, 100)) {
            Result.Reason = TEXT("Invalid validation response is missing a safe code");
        }
        return Result;
    }

    const TSharedPtr<FJsonObject>* LicenseJson = nullptr;
    if (!JsonResponse->TryGetObjectField(TEXT("license"), LicenseJson) || LicenseJson == nullptr ||
        !LicenseJson->IsValid()) {
        Result.Reason = TEXT("Valid response is missing its license");
        return Result;
    }

    FString LicenseKey;
    FString Status;
    FString Mode;
    FString PlanKey;
    const TSharedPtr<FJsonObject>* ProductJson = nullptr;
    FString ProductSlug;
    if (!(*LicenseJson)->TryGetStringField(TEXT("key"), LicenseKey) ||
        LicenseKey != ExpectedLicenseKey ||
        !(*LicenseJson)->TryGetStringField(TEXT("status"), Status) || Status != TEXT("active") ||
        !(*LicenseJson)->TryGetStringField(TEXT("mode"), Mode) ||
        !(Mode == TEXT("hardware_locked") || Mode == TEXT("floating") || Mode == TEXT("named")) ||
        !(*LicenseJson)->TryGetStringField(TEXT("plan_key"), PlanKey) ||
        !IsSafeText(PlanKey, 100) ||
        !(*LicenseJson)->TryGetObjectField(TEXT("product"), ProductJson) ||
        ProductJson == nullptr || !ProductJson->IsValid() ||
        !(*ProductJson)->TryGetStringField(TEXT("slug"), ProductSlug) ||
        ProductSlug != CurrentConfig.ProductSlug) {
        Result.Reason = TEXT("Validation response identity is inconsistent");
        return Result;
    }

    FString StartsAt;
    if ((*LicenseJson)->TryGetStringField(TEXT("starts_at"), StartsAt) && !StartsAt.IsEmpty()) {
        FDateTime ParsedStart;
        if (!FDateTime::ParseIso8601(*StartsAt, ParsedStart) || FDateTime::UtcNow() < ParsedStart) {
            Result.Reason = TEXT("License has not started");
            return Result;
        }
    }

    FString ExpiresAt;
    if ((*LicenseJson)->TryGetStringField(TEXT("expires_at"), ExpiresAt) && !ExpiresAt.IsEmpty()) {
        if (!FDateTime::ParseIso8601(*ExpiresAt, Result.ExpiresAt) ||
            FDateTime::UtcNow() >= Result.ExpiresAt) {
            Result.Reason = TEXT("License has expired or has an invalid expiry");
            return Result;
        }
        Result.bHasExpiration = true;
    }

    Result.bValid = true;
    Result.LicenseKey = LicenseKey;
    Result.Status = ParseLicenseStatus(Status);
    return Result;
}

void ULicenseSeatSubsystem::OnAutoValidationTimer() {
    if (!AutoValidationLicenseKey.IsEmpty()) {
        ValidateAsync(AutoValidationLicenseKey, FOnValidationComplete());
    }
}
