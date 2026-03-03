/**
 * ImageTool Pro - Visual Demo Application
 *
 * A GUI demo app to showcase LicenseSeat SDK integration.
 * Uses raylib + raygui for cross-platform windowing.
 *
 * Build:
 *   cd demo && cmake -B build && cmake --build build
 *   open build/imagetool_demo.app   # macOS
 *   ./build/imagetool_demo          # Linux
 */

#include "raylib.h"

#define RAYGUI_IMPLEMENTATION
#include "raygui.h"

// Include dark style (embedded)
#define GUI_DARK_STYLE_IMPLEMENTATION
#include "style_dark.h"

// LicenseSeat SDK
#include <licenseseat/licenseseat.hpp>
#include <licenseseat/events.hpp>

#include <string>
#include <cstring>
#include <memory>
#include <mutex>

// Toast notification
struct Toast {
    std::string message;
    float timer = 0.0f;
    Color color = WHITE;
    bool active = false;

    void show(const char* msg, Color col = WHITE, float duration = 2.0f) {
        message = msg;
        color = col;
        timer = duration;
        active = true;
    }

    void update(float dt) {
        if (active) {
            timer -= dt;
            if (timer <= 0) active = false;
        }
    }

    void draw(int screenWidth, int screenHeight) {
        if (!active) return;

        int textWidth = MeasureText(message.c_str(), 18);
        int boxWidth = textWidth + 40;
        int boxHeight = 44;
        int x = (screenWidth - boxWidth) / 2;
        int y = screenHeight - 100;

        // Fade out effect
        float alpha = (timer < 0.5f) ? timer * 2.0f : 1.0f;

        DrawRectangle(x, y, boxWidth, boxHeight, ColorAlpha(BLACK, 0.8f * alpha));
        DrawRectangleLinesEx({(float)x, (float)y, (float)boxWidth, (float)boxHeight}, 1,
                             ColorAlpha(color, alpha));
        DrawText(message.c_str(), x + 20, y + 13, 18, ColorAlpha(color, alpha));
    }
};

// App state
struct AppState {
    // LicenseSeat SDK client
    std::unique_ptr<licenseseat::Client> sdk;

    // License state (driven by SDK events)
    bool licensed = false;
    std::string license_key;
    std::string plan_name = "Free";
    std::string license_status;

    // Feature entitlements
    bool has_pro_filters = false;
    bool has_batch_export = false;
    bool has_cloud_sync = false;
    bool has_raw_support = false;
    bool has_updates = false;

    // UI state
    bool show_license_modal = false;
    bool show_upgrade_modal = false;
    bool show_about_modal = false;
    std::string upgrade_feature;
    char key_input[64] = "";

    // Demo state
    bool image_loaded = false;
    std::string image_name = "sample.jpg";

    // Toast notifications (thread-safe queue)
    Toast toast;
    std::mutex toast_mutex;
    std::string pending_toast_msg;
    Color pending_toast_color = WHITE;
    bool has_pending_toast = false;

    // Queue a toast from any thread (processed in main loop)
    void queue_toast(const std::string& msg, Color col = WHITE) {
        std::lock_guard<std::mutex> lock(toast_mutex);
        pending_toast_msg = msg;
        pending_toast_color = col;
        has_pending_toast = true;
    }

    // Process queued toast on main thread
    void process_pending_toast() {
        std::lock_guard<std::mutex> lock(toast_mutex);
        if (has_pending_toast) {
            toast.show(pending_toast_msg.c_str(), pending_toast_color);
            has_pending_toast = false;
        }
    }

    // Initialize SDK with event handlers
    void init_sdk() {
        licenseseat::Config config;
        config.api_key = "pk_test_9cXtKvf6rt2swMYJcg4ykiVyKFxFjWHri";
        config.product_slug = "imagetool-demo";
        config.api_url = "http://localhost:3000/api/v1";
        config.timeout_seconds = 3;
        config.verify_ssl = false;
        config.debug = true;

        // Storage for offline cache + license key persistence
        config.storage_path = "/tmp/imagetool_demo";

        // App info for telemetry
        config.app_version = "1.0.0";
        config.app_build = "100";

        // Fast intervals for development
        config.auto_validate_interval = 30.0;
        config.heartbeat_interval = 30;
        config.network_recheck_interval = 10.0;

        sdk = std::make_unique<licenseseat::Client>(config);

        // Subscribe to SDK events
        setup_event_handlers();
    }

    void setup_event_handlers() {
        // === License Lifecycle Events ===
        sdk->on(licenseseat::events::LICENSE_LOADED, [this](const std::any&) {
            queue_toast("License loaded from cache", SKYBLUE);
        });

        sdk->on(licenseseat::events::LICENSE_REVOKED, [this](const std::any&) {
            licensed = false;
            reset_entitlements();
            license_status = "License revoked";
            queue_toast("License has been revoked!", MAROON);
        });

        // === Activation Events ===
        sdk->on(licenseseat::events::ACTIVATION_START, [this](const std::any&) {
            license_status = "Activating...";
        });

        sdk->on(licenseseat::events::ACTIVATION_SUCCESS, [this](const std::any&) {
            license_status = "Activated!";
        });

        sdk->on(licenseseat::events::ACTIVATION_ERROR, [this](const std::any&) {
            queue_toast("Activation failed", MAROON);
        });

        // === Validation Events ===
        sdk->on(licenseseat::events::VALIDATION_START, [this](const std::any&) {
            // Validation starting (could show spinner)
        });

        sdk->on(licenseseat::events::VALIDATION_SUCCESS, [this](const std::any&) {
            // Online validation succeeded
        });

        sdk->on(licenseseat::events::VALIDATION_FAILED, [this](const std::any&) {
            licensed = false;
            reset_entitlements();
            license_status = "License invalid";
            queue_toast("License validation failed", MAROON);
        });

        sdk->on(licenseseat::events::VALIDATION_ERROR, [this](const std::any&) {
            queue_toast("Validation error", ORANGE);
        });

        sdk->on(licenseseat::events::VALIDATION_AUTH_FAILED, [this](const std::any&) {
            queue_toast("Authentication failed", MAROON);
        });

        sdk->on(licenseseat::events::VALIDATION_OFFLINE_SUCCESS, [this](const std::any&) {
            queue_toast("Offline validation OK", ORANGE);
        });

        sdk->on(licenseseat::events::VALIDATION_OFFLINE_FAILED, [this](const std::any&) {
            licensed = false;
            reset_entitlements();
            license_status = "Offline validation failed";
            queue_toast("Offline validation failed", MAROON);
        });

        sdk->on(licenseseat::events::VALIDATION_AUTO_FAILED, [this](const std::any&) {
            queue_toast("Auto-validation failed", ORANGE);
        });

        // === Deactivation Events ===
        sdk->on(licenseseat::events::DEACTIVATION_START, [this](const std::any&) {
            license_status = "Deactivating...";
        });

        sdk->on(licenseseat::events::DEACTIVATION_SUCCESS, [this](const std::any&) {
            license_status = "Deactivated";
        });

        sdk->on(licenseseat::events::DEACTIVATION_ERROR, [this](const std::any&) {
            queue_toast("Deactivation error", ORANGE);
        });

        // === Network Events ===
        sdk->on(licenseseat::events::NETWORK_ONLINE, [this](const std::any&) {
            queue_toast("Back online", GREEN);
        });

        sdk->on(licenseseat::events::NETWORK_OFFLINE, [this](const std::any&) {
            queue_toast("Switched to offline mode", ORANGE);
        });

        // === Auto-Validation Events ===
        sdk->on(licenseseat::events::AUTOVALIDATION_CYCLE, [this](const std::any&) {
            // Auto-validation cycle completed (silent)
        });

        sdk->on(licenseseat::events::AUTOVALIDATION_STOPPED, [this](const std::any&) {
            // Auto-validation stopped (silent)
        });

        // === Offline Token Events ===
        sdk->on(licenseseat::events::OFFLINE_TOKEN_FETCHING, [this](const std::any&) {
            // Fetching offline token (silent)
        });

        sdk->on(licenseseat::events::OFFLINE_TOKEN_FETCHED, [this](const std::any&) {
            queue_toast("Offline token synced", GREEN);
        });

        sdk->on(licenseseat::events::OFFLINE_TOKEN_FETCH_ERROR, [this](const std::any&) {
            queue_toast("Failed to sync offline token", ORANGE);
        });

        sdk->on(licenseseat::events::OFFLINE_TOKEN_READY, [this](const std::any&) {
            // Offline token ready (silent)
        });

        sdk->on(licenseseat::events::OFFLINE_TOKEN_VERIFIED, [this](const std::any&) {
            // Offline token verified (silent)
        });

        sdk->on(licenseseat::events::OFFLINE_TOKEN_VERIFICATION_FAILED, [this](const std::any&) {
            queue_toast("Offline token invalid", MAROON);
        });

        // === Heartbeat Events ===
        sdk->on(licenseseat::events::HEARTBEAT_SUCCESS, [this](const std::any&) {
            // Heartbeat success (silent)
        });

        sdk->on(licenseseat::events::HEARTBEAT_ERROR, [this](const std::any&) {
            // Heartbeat failed (silent - network issues are reported separately)
        });

        // === SDK Events ===
        sdk->on(licenseseat::events::SDK_RESET, [this](const std::any&) {
            licensed = false;
            reset_entitlements();
            license_key.clear();
            plan_name = "Free";
        });

        sdk->on(licenseseat::events::SDK_ERROR, [this](const std::any&) {
            queue_toast("SDK error", MAROON);
        });
    }

    void enable_all_entitlements() {
        has_pro_filters = true;
        has_batch_export = true;
        has_cloud_sync = true;
        has_raw_support = true;
        has_updates = true;
    }

    void reset_entitlements() {
        has_pro_filters = false;
        has_batch_export = false;
        has_cloud_sync = false;
        has_raw_support = false;
        has_updates = false;
    }

    // Update entitlements from license (if specific entitlements are defined)
    void update_entitlements_from_license(const licenseseat::License& license) {
        reset_entitlements();

        for (const auto& ent : license.active_entitlements()) {
            if (ent.key == "pro_filters") has_pro_filters = true;
            else if (ent.key == "batch_export") has_batch_export = true;
            else if (ent.key == "cloud_sync") has_cloud_sync = true;
            else if (ent.key == "raw_support") has_raw_support = true;
            else if (ent.key == "updates") has_updates = true;
        }

        // If no specific entitlements but license valid, enable all (full Pro)
        if (license.is_valid() && license.active_entitlements().empty()) {
            enable_all_entitlements();
        }
    }

    // Restore license on startup using SDK
    void restore_on_startup() {
        auto result = sdk->restore_license();

        switch (result.status) {
            case licenseseat::ClientStatus::Active:
                // Online validated
                licensed = true;
                if (result.license) {
                    license_key = result.license->key();
                    plan_name = result.license->plan_key().empty() ? "Pro" : result.license->plan_key();
                    update_entitlements_from_license(*result.license);
                    strncpy(key_input, license_key.c_str(), 63);
                }
                toast.show("License verified", GREEN);
                break;

            case licenseseat::ClientStatus::OfflineValid:
                // Offline validated
                licensed = true;
                if (result.license) {
                    license_key = result.license->key();
                    plan_name = result.license->plan_key().empty() ? "Pro" : result.license->plan_key();
                    update_entitlements_from_license(*result.license);
                    strncpy(key_input, license_key.c_str(), 63);
                }
                toast.show("Loaded from offline cache", ORANGE);
                break;

            case licenseseat::ClientStatus::OfflineInvalid:
                // Offline validation failed
                toast.show("Offline validation failed", MAROON, 4.0f);
                break;

            case licenseseat::ClientStatus::Invalid:
                // License invalid/revoked
                toast.show("License is no longer valid", MAROON, 4.0f);
                break;

            case licenseseat::ClientStatus::Inactive:
                // No cached license
                break;

            case licenseseat::ClientStatus::Pending:
                // Should not happen for sync call
                break;
        }
    }
};

void DrawLicenseStatus(AppState& state, int x, int y) {
    int badgeW = 140;
    int badgeH = 44;
    Rectangle badge = { (float)x, (float)y, (float)badgeW, (float)badgeH };

    if (state.licensed) {
        DrawRectangleRec(badge, ColorAlpha(GREEN, 0.2f));
        DrawRectangleLinesEx(badge, 1, GREEN);
        DrawText("PRO", x + 10, y + 8, 14, GREEN);
        DrawText(state.plan_name.c_str(), x + 10, y + 25, 11, ColorAlpha(GREEN, 0.8f));
    } else {
        DrawRectangleRec(badge, ColorAlpha(GRAY, 0.15f));
        DrawRectangleLinesEx(badge, 1, DARKGRAY);
        DrawText("FREE", x + 10, y + 8, 14, LIGHTGRAY);
        DrawText("Limited", x + 10, y + 25, 11, GRAY);
    }
}

void DrawConnectionStatus(AppState& state, int x, int y) {
    if (!state.sdk) return;

    auto status = state.sdk->get_client_status();
    bool is_online = state.sdk->is_online();

    Color statusColor;
    const char* statusText;
    const char* modeText = "";

    switch (status) {
        case licenseseat::ClientStatus::Active:
            statusColor = GREEN;
            statusText = "Online";
            modeText = "(live)";
            break;
        case licenseseat::ClientStatus::OfflineValid:
            statusColor = ORANGE;
            statusText = "Offline";
            modeText = "(cached)";
            break;
        case licenseseat::ClientStatus::OfflineInvalid:
            statusColor = MAROON;
            statusText = "Offline";
            modeText = "(invalid)";
            break;
        default:
            statusColor = is_online ? GRAY : ORANGE;
            statusText = is_online ? "Online" : "Offline";
            break;
    }

    DrawCircle(x + 6, y + 8, 5, statusColor);
    DrawText(statusText, x + 16, y, 12, statusColor);

    if (state.licensed && modeText[0] != '\0') {
        DrawText(modeText, x + 16, y + 14, 10, GRAY);
    }
}

bool DrawFeatureButton(const char* label, bool enabled, bool is_pro, int x, int y, int w, int h, AppState& state) {
    Rectangle btn = { (float)x, (float)y, (float)w, (float)h };
    bool clicked = false;

    if (is_pro && !enabled) {
        bool hover = CheckCollisionPointRec(GetMousePosition(), btn);

        Color bg = hover ? GetColor(0x3a3a3aff) : GetColor(0x2a2a2aff);
        DrawRectangleRec(btn, bg);
        DrawRectangleLinesEx(btn, 1, GetColor(0x4a4a4aff));
        DrawText(label, x + 10, y + (h - 14) / 2, 14, GetColor(0x909090ff));

        int badgeX = x + w - 42;
        int badgeY = y + (h - 16) / 2;
        DrawRectangle(badgeX, badgeY, 36, 16, ColorAlpha(GOLD, 0.3f));
        DrawRectangleLinesEx({(float)badgeX, (float)badgeY, 36, 16}, 1, GOLD);
        DrawText("PRO", badgeX + 6, badgeY + 2, 10, GOLD);

        if (hover && IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
            state.show_upgrade_modal = true;
            state.upgrade_feature = label;
        }
    } else {
        clicked = GuiButton(btn, label);
    }

    return clicked;
}

void DrawUpgradeModal(AppState& state) {
    if (!state.show_upgrade_modal) return;

    DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), ColorAlpha(BLACK, 0.7f));

    int w = 400, h = 220;
    int x = (GetScreenWidth() - w) / 2;
    int y = (GetScreenHeight() - h) / 2;

    DrawRectangle(x, y, w, h, GetColor(0x2a2a2aff));
    DrawRectangleLinesEx({(float)x, (float)y, (float)w, (float)h}, 2, GOLD);

    DrawText("Pro Feature Required", x + 20, y + 20, 20, GOLD);
    DrawText(TextFormat("\"%s\" needs a Pro license.", state.upgrade_feature.c_str()),
             x + 20, y + 55, 14, LIGHTGRAY);

    DrawText("Upgrade to unlock all features:", x + 20, y + 85, 14, GRAY);
    DrawText("* Professional filters", x + 30, y + 108, 13, GRAY);
    DrawText("* Batch processing", x + 30, y + 125, 13, GRAY);
    DrawText("* Cloud sync", x + 30, y + 142, 13, GRAY);

    if (GuiButton({(float)(x + 20), (float)(y + h - 50), 130, 34}, "Activate")) {
        state.show_upgrade_modal = false;
        state.show_license_modal = true;
    }

    if (GuiButton({(float)(x + w - 90), (float)(y + h - 50), 70, 34}, "Close")) {
        state.show_upgrade_modal = false;
    }
}

void DrawLicenseModal(AppState& state) {
    if (!state.show_license_modal) return;

    DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), ColorAlpha(BLACK, 0.7f));

    int w = 520, h = 280;
    int x = (GetScreenWidth() - w) / 2;
    int y = (GetScreenHeight() - h) / 2;

    DrawRectangle(x, y, w, h, GetColor(0x2a2a2aff));
    DrawRectangleLinesEx({(float)x, (float)y, (float)w, (float)h}, 2, GetColor(0x555555ff));

    DrawText("Activate License", x + 20, y + 20, 20, WHITE);
    DrawText("Enter your license key:", x + 20, y + 55, 14, LIGHTGRAY);

    // Clear button
    if (GuiButton({(float)(x + w - 160), (float)(y + 80), 55, 34}, "Clear")) {
        memset(state.key_input, 0, sizeof(state.key_input));
    }

    // Paste button
    if (GuiButton({(float)(x + w - 95), (float)(y + 80), 75, 34}, "Paste")) {
        const char* clipboard = GetClipboardText();
        if (clipboard) {
            strncpy(state.key_input, clipboard, 63);
            state.key_input[63] = '\0';
        }
    }

    // Cmd+V / Ctrl+V paste shortcut
    bool cmdOrCtrl = IsKeyDown(KEY_LEFT_SUPER) || IsKeyDown(KEY_RIGHT_SUPER) ||
                     IsKeyDown(KEY_LEFT_CONTROL) || IsKeyDown(KEY_RIGHT_CONTROL);
    if (cmdOrCtrl && IsKeyPressed(KEY_V)) {
        const char* clipboard = GetClipboardText();
        if (clipboard) {
            strncpy(state.key_input, clipboard, 63);
            state.key_input[63] = '\0';
        }
    }

    Rectangle inputBox = { (float)(x + 20), (float)(y + 80), (float)(w - 190), 34 };
    GuiTextBox(inputBox, state.key_input, 64, true);

    DrawText("Enter a valid LicenseSeat license key", x + 20, y + 122, 12, GRAY);

    if (!state.license_status.empty()) {
        Color statusColor = state.licensed ? GREEN : MAROON;
        DrawText(state.license_status.c_str(), x + 20, y + 150, 14, statusColor);
    }

    if (GuiButton({(float)(x + 20), (float)(y + h - 55), 120, 36}, "Activate")) {
        std::string key(state.key_input);

        if (!key.empty() && state.sdk) {
            auto result = state.sdk->activate(key);

            // Treat DeviceAlreadyActivated as success - device is already good
            bool activation_ok = result.is_ok() ||
                result.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated;

            if (activation_ok) {
                // Validate to get full license details
                auto validate_result = state.sdk->validate(key);

                if (validate_result.is_ok()) {
                    const auto& validation = validate_result.value();
                    const auto& license = validation.license;

                    state.plan_name = license.plan_key().empty() ? "Pro" : license.plan_key();

                    // Valid license = full Pro access (demo app enables all features)
                    // In production, you'd check specific entitlements from license.active_entitlements()
                    state.enable_all_entitlements();

                    state.licensed = true;
                    state.license_key = key;
                    state.license_status = validation.valid ? "License activated!" : validation.message;
                    state.toast.show("Pro license activated!", GREEN);

                    // SDK handles: heartbeat, auto-validation, offline sync
                    state.sdk->start_heartbeat(key);
                    state.sdk->start_auto_validation(key);
                    state.sdk->sync_offline_assets();
                } else {
                    // Validation failed but activation worked - enable features anyway
                    state.enable_all_entitlements();
                    state.licensed = true;
                    state.license_key = key;
                    state.license_status = "Activated (offline)";
                    state.toast.show("License activated!", GREEN);

                    state.sdk->start_heartbeat(key);
                    state.sdk->start_auto_validation(key);
                    state.sdk->sync_offline_assets();
                }
            } else {
                std::string error_msg = result.error_message();
                if (error_msg.empty()) error_msg = "Activation failed";
                state.license_status = error_msg;
                state.toast.show(error_msg.c_str(), MAROON);
            }
        } else if (key.empty()) {
            state.license_status = "Please enter a license key";
        }
    }

    if (GuiButton({(float)(x + 150), (float)(y + h - 55), 110, 36}, "Deactivate")) {
        if (state.sdk && !state.license_key.empty()) {
            (void)state.sdk->deactivate(state.license_key, state.sdk->device_id());
        }

        // SDK reset clears all state and stops timers
        if (state.sdk) {
            state.sdk->reset();
        }

        state.licensed = false;
        state.license_key.clear();
        state.plan_name = "Free";
        state.license_status = "Deactivated";
        state.reset_entitlements();
        memset(state.key_input, 0, sizeof(state.key_input));
        state.toast.show("License deactivated", GRAY);
    }

    // Clear All Data button - resets SDK and clears all cached license data
    if (GuiButton({(float)(x + 270), (float)(y + h - 55), 110, 36}, "Clear Data")) {
        if (state.sdk) {
            // SDK reset clears all cached data, stops timers, emits SDK_RESET event
            state.sdk->reset();
        }

        state.licensed = false;
        state.license_key.clear();
        state.plan_name = "Free";
        state.license_status = "All data cleared";
        state.reset_entitlements();
        memset(state.key_input, 0, sizeof(state.key_input));
        state.toast.show("All license data cleared", ORANGE);
    }

    if (GuiButton({(float)(x + w - 80), (float)(y + h - 55), 60, 36}, "Close")) {
        state.show_license_modal = false;
    }
}

void DrawAboutModal(AppState& state) {
    if (!state.show_about_modal) return;

    DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), ColorAlpha(BLACK, 0.7f));

    int w = 350, h = 200;
    int x = (GetScreenWidth() - w) / 2;
    int y = (GetScreenHeight() - h) / 2;

    DrawRectangle(x, y, w, h, GetColor(0x2a2a2aff));
    DrawRectangleLinesEx({(float)x, (float)y, (float)w, (float)h}, 2, GetColor(0x555555ff));

    DrawText("About ImageTool Pro", x + 20, y + 20, 18, WHITE);
    DrawText("Version 1.0.0", x + 20, y + 50, 14, GRAY);
    DrawText("Demo app with LicenseSeat SDK integration", x + 20, y + 75, 13, LIGHTGRAY);
    DrawText("for license validation & entitlements.", x + 20, y + 92, 13, LIGHTGRAY);
    DrawText("Built with raylib + raygui + LicenseSeat", x + 20, y + 120, 12, GRAY);

    if (GuiButton({(float)(x + w - 90), (float)(y + h - 50), 70, 34}, "Close")) {
        state.show_about_modal = false;
    }
}

int main() {
    const int screenWidth = 1000;
    const int screenHeight = 700;

    SetConfigFlags(FLAG_WINDOW_RESIZABLE | FLAG_VSYNC_HINT);
    InitWindow(screenWidth, screenHeight, "ImageTool Pro");
    SetWindowMinSize(800, 600);
    SetTargetFPS(60);

    GuiLoadStyleDark();
    GuiSetStyle(DEFAULT, TEXT_SIZE, 16);
    GuiSetStyle(DEFAULT, TEXT_SPACING, 1);

    AppState state;
    state.init_sdk();

    // Restore license on startup - SDK handles online/offline automatically
    state.restore_on_startup();

    while (!WindowShouldClose()) {
        float dt = GetFrameTime();
        state.toast.update(dt);
        state.process_pending_toast();

        int w = GetScreenWidth();
        int h = GetScreenHeight();

        GuiUnlock();
        GuiSetState(STATE_NORMAL);

        bool modalOpen = state.show_license_modal || state.show_upgrade_modal || state.show_about_modal;

        BeginDrawing();
        ClearBackground(GetColor(0x1e1e1eff));

        // === Header ===
        int headerH = 54;
        DrawRectangle(0, 0, w, headerH, GetColor(0x252525ff));
        DrawLine(0, headerH, w, headerH, GetColor(0x3a3a3aff));

        DrawText("ImageTool Pro", 20, 17, 20, WHITE);
        DrawText("v1.0.0", 165, 22, 12, GRAY);

        DrawConnectionStatus(state, w - 280, 15);
        DrawLicenseStatus(state, w - 160, 5);

        // === Sidebar ===
        int sidebarW = 200;
        DrawRectangle(0, headerH, sidebarW, h - headerH - 28, GetColor(0x222222ff));
        DrawLine(sidebarW, headerH, sidebarW, h - 28, GetColor(0x3a3a3aff));

        int btnX = 12;
        int btnY = headerH + 16;
        int btnW = sidebarW - 24;
        int btnH = 32;
        int btnGap = 38;

        DrawText("BASIC TOOLS", btnX, btnY, 11, GRAY);
        btnY += 22;

        if (modalOpen) GuiLock();

        if (DrawFeatureButton("Open Image", true, false, btnX, btnY, btnW, btnH, state)) {
            state.image_loaded = true;
            state.image_name = "photo_001.jpg";
            state.toast.show("Image loaded: photo_001.jpg", SKYBLUE);
        }
        btnY += btnGap;

        if (DrawFeatureButton("Crop & Rotate", true, false, btnX, btnY, btnW, btnH, state)) {
            state.toast.show("Crop tool activated", LIGHTGRAY);
        }
        btnY += btnGap;

        if (DrawFeatureButton("Adjustments", true, false, btnX, btnY, btnW, btnH, state)) {
            state.toast.show("Brightness/Contrast panel", LIGHTGRAY);
        }
        btnY += btnGap;

        if (DrawFeatureButton("Export JPG/PNG", true, false, btnX, btnY, btnW, btnH, state)) {
            state.toast.show("Exported as output.png", GREEN);
        }
        btnY += btnGap + 14;

        DrawText("PRO FEATURES", btnX, btnY, 11, GOLD);
        btnY += 22;

        if (DrawFeatureButton("Pro Filters", state.has_pro_filters, true, btnX, btnY, btnW, btnH, state)) {
            state.toast.show("Cinematic LUT applied", GOLD);
        }
        btnY += btnGap;

        if (DrawFeatureButton("AI Enhance", state.has_pro_filters, true, btnX, btnY, btnW, btnH, state)) {
            state.toast.show("AI enhancement complete", GOLD);
        }
        btnY += btnGap;

        if (DrawFeatureButton("Batch Process", state.has_batch_export, true, btnX, btnY, btnW, btnH, state)) {
            state.toast.show("Processed 10 images", GOLD);
        }
        btnY += btnGap;

        if (DrawFeatureButton("Cloud Sync", state.has_cloud_sync, true, btnX, btnY, btnW, btnH, state)) {
            state.toast.show("Synced with cloud", GOLD);
        }
        btnY += btnGap;

        if (DrawFeatureButton("RAW Support", state.has_raw_support, true, btnX, btnY, btnW, btnH, state)) {
            state.toast.show("RAW file loaded", GOLD);
        }
        btnY += btnGap + 14;

        DrawText("UPDATES", btnX, btnY, 11, SKYBLUE);
        btnY += 22;

        if (DrawFeatureButton("Check Updates", state.has_updates, true, btnX, btnY, btnW, btnH, state)) {
            state.toast.show("You're on the latest version!", SKYBLUE);
        }

        // Bottom buttons
        int bottomY = h - 28 - 90;
        if (GuiButton({(float)btnX, (float)bottomY, (float)btnW, 32},
                      state.licensed ? "Manage License" : "Activate License")) {
            if (!state.license_key.empty()) {
                strncpy(state.key_input, state.license_key.c_str(), 63);
                state.key_input[63] = '\0';
            }
            state.show_license_modal = true;
        }

        if (GuiButton({(float)btnX, (float)(bottomY + 40), (float)btnW, 32}, "About")) {
            state.show_about_modal = true;
        }

        // === Canvas ===
        int canvasX = sidebarW + 16;
        int canvasY = headerH + 16;
        int canvasW = w - sidebarW - 32;
        int canvasH = h - headerH - 60;

        DrawRectangle(canvasX, canvasY, canvasW, canvasH, GetColor(0x1a1a1aff));
        DrawRectangleLinesEx({(float)canvasX, (float)canvasY, (float)canvasW, (float)canvasH}, 1, GetColor(0x333333ff));

        if (state.image_loaded) {
            DrawText(state.image_name.c_str(), canvasX + 16, canvasY + 12, 14, LIGHTGRAY);

            int imgX = canvasX + 30;
            int imgY = canvasY + 40;
            int imgW = canvasW - 60;
            int imgH = canvasH - 80;
            DrawRectangle(imgX, imgY, imgW, imgH, GetColor(0x252525ff));
            DrawRectangleLinesEx({(float)imgX, (float)imgY, (float)imgW, (float)imgH}, 1, GetColor(0x404040ff));

            const char* txt = "[ Image Preview ]";
            int txtW = MeasureText(txt, 18);
            DrawText(txt, imgX + (imgW - txtW) / 2, imgY + imgH / 2 - 9, 18, GRAY);
        } else {
            const char* txt1 = "No image loaded";
            const char* txt2 = "Click 'Open Image' to start";
            DrawText(txt1, canvasX + (canvasW - MeasureText(txt1, 18)) / 2, canvasY + canvasH / 2 - 30, 18, GRAY);
            DrawText(txt2, canvasX + (canvasW - MeasureText(txt2, 14)) / 2, canvasY + canvasH / 2, 14, DARKGRAY);

            if (GuiButton({(float)(canvasX + canvasW / 2 - 60), (float)(canvasY + canvasH / 2 + 30), 120, 34}, "Open Image")) {
                state.image_loaded = true;
                state.image_name = "photo_001.jpg";
                state.toast.show("Image loaded!", SKYBLUE);
            }
        }

        // === Status bar ===
        int statusY = h - 28;
        DrawRectangle(0, statusY, w, 28, GetColor(0x202020ff));
        DrawLine(0, statusY, w, statusY, GetColor(0x3a3a3aff));

        const char* statusTxt = state.licensed ? "Pro License Active" : "Free Edition";
        DrawText(statusTxt, 12, statusY + 7, 12, GRAY);

        // SDK Status in bottom right
        if (state.sdk) {
            auto clientStatus = state.sdk->get_client_status();
            const char* sdkStatusText = "";
            Color sdkStatusColor = GRAY;

            switch (clientStatus) {
                case licenseseat::ClientStatus::Active:
                    sdkStatusText = "SDK: Active";
                    sdkStatusColor = GREEN;
                    break;
                case licenseseat::ClientStatus::OfflineValid:
                    sdkStatusText = "SDK: Offline (Valid)";
                    sdkStatusColor = ORANGE;
                    break;
                case licenseseat::ClientStatus::OfflineInvalid:
                    sdkStatusText = "SDK: Offline (Invalid)";
                    sdkStatusColor = MAROON;
                    break;
                case licenseseat::ClientStatus::Inactive:
                    sdkStatusText = "SDK: Inactive";
                    sdkStatusColor = GRAY;
                    break;
                case licenseseat::ClientStatus::Invalid:
                    sdkStatusText = "SDK: Invalid";
                    sdkStatusColor = MAROON;
                    break;
                case licenseseat::ClientStatus::Pending:
                    sdkStatusText = "SDK: Pending...";
                    sdkStatusColor = SKYBLUE;
                    break;
            }

            int sdkTextWidth = MeasureText(sdkStatusText, 12);
            DrawText(sdkStatusText, w - sdkTextWidth - 12, statusY + 7, 12, sdkStatusColor);
        }

        // === Modals ===
        GuiUnlock();
        DrawUpgradeModal(state);
        DrawLicenseModal(state);
        DrawAboutModal(state);

        // === Toast ===
        state.toast.draw(w, h);

        EndDrawing();
    }

    CloseWindow();
    return 0;
}
