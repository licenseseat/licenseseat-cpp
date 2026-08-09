// Copyright LicenseSeat. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "LicenseSeatTypes.generated.h"

/**
 * License status enumeration
 */
UENUM(BlueprintType)
enum class ELicenseStatus : uint8 {
    Unknown UMETA(DisplayName = "Unknown"),
    Active UMETA(DisplayName = "Active"),
    Expired UMETA(DisplayName = "Expired"),
    Revoked UMETA(DisplayName = "Revoked"),
    Suspended UMETA(DisplayName = "Suspended"),
    Pending UMETA(DisplayName = "Pending")
};

/**
 * License validation result
 */
USTRUCT(BlueprintType)
struct LICENSESEAT_API FLicenseValidationResult {
    GENERATED_BODY()

    /** Whether the license is valid */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    bool bValid = false;

    /** Reason for invalid status (if not valid) */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    FString Reason;

    /** License key */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    FString LicenseKey;

    /** License status */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    ELicenseStatus Status = ELicenseStatus::Unknown;

    /** Whether this was an offline validation */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    bool bOffline = false;

    /** Expiration date (if applicable) */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    FDateTime ExpiresAt;

    /** Whether the license has an expiration date */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    bool bHasExpiration = false;
};

/**
 * License activation result
 */
USTRUCT(BlueprintType)
struct LICENSESEAT_API FLicenseActivationResult {
    GENERATED_BODY()

    /** Whether activation succeeded */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    bool bSuccess = false;

    /** Error message if failed */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    FString ErrorMessage;

    /** Activation ID */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    FString ActivationId;

    /** Device fingerprint (legacy field name) */
    UPROPERTY(BlueprintReadOnly, Category = "LicenseSeat")
    FString DeviceId;
};

/**
 * LicenseSeat configuration
 */
USTRUCT(BlueprintType)
struct LICENSESEAT_API FLicenseSeatConfig {
    GENERATED_BODY()

    /** API key for authentication */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "LicenseSeat")
    FString ApiKey;

    /** Product slug */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "LicenseSeat")
    FString ProductSlug;

    /** API base URL (defaults to LicenseSeat cloud) */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "LicenseSeat")
    FString ApiUrl = TEXT("https://licenseseat.com/api/v1");

    /** Reserved for a future authenticated offline implementation. Online-only today. */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "LicenseSeat")
    FString OfflinePublicKey;

    /** Reserved for future offline support; has no effect in the current plugin. */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "LicenseSeat")
    int32 MaxOfflineDays = 30;

    /** Auto-validation interval in seconds (0 to disable) */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "LicenseSeat")
    float AutoValidateInterval = 300.0f;

    /** Request timeout in seconds (1-300). */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "LicenseSeat")
    float RequestTimeoutSeconds = 30.0f;

    /** Maximum accepted JSON response size in bytes. */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "LicenseSeat")
    int32 MaxResponseBytes = 1024 * 1024;

    /** Explicitly permit plaintext HTTP for localhost development only. */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "LicenseSeat")
    bool bAllowInsecureLoopback = false;
};

/**
 * Delegate for async validation results
 */
DECLARE_DYNAMIC_DELEGATE_OneParam(FOnValidationComplete, const FLicenseValidationResult&, Result);

/**
 * Delegate for async activation results
 */
DECLARE_DYNAMIC_DELEGATE_OneParam(FOnActivationComplete, const FLicenseActivationResult&, Result);

/**
 * Multicast delegate for license status changes
 */
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FOnLicenseStatusChanged,
                                            const FLicenseValidationResult&, NewStatus);
