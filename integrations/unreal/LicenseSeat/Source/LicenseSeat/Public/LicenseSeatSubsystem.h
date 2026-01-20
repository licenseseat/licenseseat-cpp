// Copyright LicenseSeat. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "Subsystems/GameInstanceSubsystem.h"
#include "LicenseSeatTypes.h"
#include "LicenseSeatSubsystem.generated.h"

/**
 * LicenseSeat Game Instance Subsystem
 *
 * Provides license validation and management for your game.
 * Access via: GetGameInstance()->GetSubsystem<ULicenseSeatSubsystem>()
 *
 * Features:
 * - Online license validation
 * - Offline license verification (Ed25519 signatures)
 * - Device-based activation
 * - Automatic re-validation
 * - Blueprint support
 *
 * Example usage:
 * @code
 * auto* Subsystem = GetGameInstance()->GetSubsystem<ULicenseSeatSubsystem>();
 * Subsystem->Initialize(Config);
 * Subsystem->ValidateAsync(LicenseKey, FOnValidationComplete::CreateLambda(...));
 * @endcode
 */
UCLASS()
class LICENSESEAT_API ULicenseSeatSubsystem : public UGameInstanceSubsystem
{
    GENERATED_BODY()

public:
    //~ USubsystem interface
    virtual void Initialize(FSubsystemCollectionBase& Collection) override;
    virtual void Deinitialize() override;

    /**
     * Initialize the subsystem with configuration
     * Call this before using any other methods
     */
    UFUNCTION(BlueprintCallable, Category = "LicenseSeat")
    void InitializeWithConfig(const FLicenseSeatConfig& Config);

    // ==================== Synchronous API ====================

    /**
     * Validate a license key (blocking)
     * @param LicenseKey The license key to validate
     * @return Validation result
     */
    UFUNCTION(BlueprintCallable, Category = "LicenseSeat")
    FLicenseValidationResult Validate(const FString& LicenseKey);

    /**
     * Activate a license on this device (blocking)
     * @param LicenseKey The license key to activate
     * @return Activation result
     */
    UFUNCTION(BlueprintCallable, Category = "LicenseSeat")
    FLicenseActivationResult Activate(const FString& LicenseKey);

    /**
     * Deactivate the current license (blocking)
     * @param LicenseKey The license key to deactivate
     * @return Whether deactivation succeeded
     */
    UFUNCTION(BlueprintCallable, Category = "LicenseSeat")
    bool Deactivate(const FString& LicenseKey);

    // ==================== Asynchronous API ====================

    /**
     * Validate a license key asynchronously
     * @param LicenseKey The license key to validate
     * @param Callback Called when validation completes
     */
    UFUNCTION(BlueprintCallable, Category = "LicenseSeat")
    void ValidateAsync(const FString& LicenseKey, FOnValidationComplete Callback);

    /**
     * Activate a license asynchronously
     * @param LicenseKey The license key to activate
     * @param Callback Called when activation completes
     */
    UFUNCTION(BlueprintCallable, Category = "LicenseSeat")
    void ActivateAsync(const FString& LicenseKey, FOnActivationComplete Callback);

    // ==================== Status Queries ====================

    /**
     * Get the current license status
     * @return Current validation result
     */
    UFUNCTION(BlueprintCallable, BlueprintPure, Category = "LicenseSeat")
    FLicenseValidationResult GetStatus() const;

    /**
     * Check if there's a valid license
     * @return True if the current license is valid
     */
    UFUNCTION(BlueprintCallable, BlueprintPure, Category = "LicenseSeat")
    bool IsLicenseValid() const;

    /**
     * Get the device identifier
     * @return Unique device ID used for activations
     */
    UFUNCTION(BlueprintCallable, BlueprintPure, Category = "LicenseSeat")
    FString GetDeviceId() const;

    // ==================== Auto-Validation ====================

    /**
     * Start automatic license re-validation
     * @param LicenseKey The license key to validate periodically
     */
    UFUNCTION(BlueprintCallable, Category = "LicenseSeat")
    void StartAutoValidation(const FString& LicenseKey);

    /**
     * Stop automatic license re-validation
     */
    UFUNCTION(BlueprintCallable, Category = "LicenseSeat")
    void StopAutoValidation();

    /**
     * Check if auto-validation is running
     */
    UFUNCTION(BlueprintCallable, BlueprintPure, Category = "LicenseSeat")
    bool IsAutoValidationRunning() const;

    // ==================== Events ====================

    /**
     * Event fired when license status changes
     */
    UPROPERTY(BlueprintAssignable, Category = "LicenseSeat")
    FOnLicenseStatusChanged OnLicenseStatusChanged;

private:
    /** Configuration */
    FLicenseSeatConfig CurrentConfig;

    /** Whether the subsystem has been initialized */
    bool bIsInitialized = false;

    /** Current license status */
    FLicenseValidationResult CurrentStatus;

    /** Auto-validation timer handle */
    FTimerHandle AutoValidationTimerHandle;

    /** License key for auto-validation */
    FString AutoValidationLicenseKey;

    /** Generate device ID using platform-specific methods */
    FString GenerateDeviceId() const;

    /** Make HTTP request to LicenseSeat API */
    void MakeApiRequest(const FString& Endpoint, const FString& Body,
                        TFunction<void(bool bSuccess, const FString& Response)> Callback);

    /** Parse validation response */
    FLicenseValidationResult ParseValidationResponse(const FString& Response);

    /** Handle auto-validation timer */
    void OnAutoValidationTimer();
};
