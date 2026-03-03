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

#include <string>
#include <cstring>

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
    // License state (will be controlled by LicenseSeat SDK later)
    bool licensed = false;
    std::string license_key;
    std::string plan_name = "Free";
    std::string license_status;

    // Feature entitlements
    bool has_pro_filters = false;
    bool has_batch_export = false;
    bool has_cloud_sync = false;
    bool has_raw_support = false;

    // UI state
    bool show_license_modal = false;
    bool show_upgrade_modal = false;
    bool show_about_modal = false;
    std::string upgrade_feature;
    char key_input[64] = "";

    // Demo state
    bool image_loaded = false;
    std::string image_name = "sample.jpg";

    // Toast notifications
    Toast toast;
};

void DrawLicenseStatus(AppState& state, int x, int y) {
    // Compact badge
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

bool DrawFeatureButton(const char* label, bool enabled, bool is_pro, int x, int y, int w, int h, AppState& state) {
    Rectangle btn = { (float)x, (float)y, (float)w, (float)h };
    bool clicked = false;

    if (is_pro && !enabled) {
        // Locked pro feature - custom draw + simple click detection
        bool hover = CheckCollisionPointRec(GetMousePosition(), btn);

        // Background
        Color bg = hover ? GetColor(0x3a3a3aff) : GetColor(0x2a2a2aff);
        DrawRectangleRec(btn, bg);
        DrawRectangleLinesEx(btn, 1, GetColor(0x4a4a4aff));

        // Label
        DrawText(label, x + 10, y + (h - 14) / 2, 14, GetColor(0x909090ff));

        // PRO badge
        int badgeX = x + w - 42;
        int badgeY = y + (h - 16) / 2;
        DrawRectangle(badgeX, badgeY, 36, 16, ColorAlpha(GOLD, 0.3f));
        DrawRectangleLinesEx({(float)badgeX, (float)badgeY, 36, 16}, 1, GOLD);
        DrawText("PRO", badgeX + 6, badgeY + 2, 10, GOLD);

        // Click on RELEASE (like GuiButton)
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
    DrawText("• Professional filters", x + 30, y + 108, 13, GRAY);
    DrawText("• Batch processing", x + 30, y + 125, 13, GRAY);
    DrawText("• Cloud sync", x + 30, y + 142, 13, GRAY);

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

    int w = 460, h = 280;
    int x = (GetScreenWidth() - w) / 2;
    int y = (GetScreenHeight() - h) / 2;

    DrawRectangle(x, y, w, h, GetColor(0x2a2a2aff));
    DrawRectangleLinesEx({(float)x, (float)y, (float)w, (float)h}, 2, GetColor(0x555555ff));

    DrawText("Activate License", x + 20, y + 20, 20, WHITE);
    DrawText("Enter your license key:", x + 20, y + 55, 14, LIGHTGRAY);

    Rectangle inputBox = { (float)(x + 20), (float)(y + 80), (float)(w - 40), 34 };
    GuiTextBox(inputBox, state.key_input, 64, true);

    DrawText("Tip: Use 'DEMO-PRO-1234' to test Pro features", x + 20, y + 122, 12, GRAY);

    if (!state.license_status.empty()) {
        Color statusColor = state.licensed ? GREEN : MAROON;
        DrawText(state.license_status.c_str(), x + 20, y + 150, 14, statusColor);
    }

    if (GuiButton({(float)(x + 20), (float)(y + h - 55), 120, 36}, "Activate")) {
        std::string key(state.key_input);

        // TODO: Replace with LicenseSeat SDK call
        if (key == "DEMO-PRO-1234" || key == "demo") {
            state.licensed = true;
            state.license_key = key;
            state.plan_name = "Pro Annual";
            state.license_status = "License activated!";
            state.has_pro_filters = true;
            state.has_batch_export = true;
            state.has_cloud_sync = true;
            state.has_raw_support = true;
            state.toast.show("Pro license activated!", GREEN);
        } else if (!key.empty()) {
            state.license_status = "Invalid license key";
            state.toast.show("Invalid license key", MAROON);
        }
    }

    if (GuiButton({(float)(x + 150), (float)(y + h - 55), 120, 36}, "Deactivate")) {
        state.licensed = false;
        state.license_key.clear();
        state.plan_name = "Free";
        state.license_status = "Deactivated";
        state.has_pro_filters = false;
        state.has_batch_export = false;
        state.has_cloud_sync = false;
        state.has_raw_support = false;
        memset(state.key_input, 0, sizeof(state.key_input));
        state.toast.show("License deactivated", GRAY);
    }

    if (GuiButton({(float)(x + w - 90), (float)(y + h - 55), 70, 36}, "Close")) {
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
    DrawText("A demo app showcasing LicenseSeat SDK", x + 20, y + 75, 13, LIGHTGRAY);
    DrawText("integration for C++ applications.", x + 20, y + 92, 13, LIGHTGRAY);
    DrawText("Built with raylib + raygui", x + 20, y + 120, 12, GRAY);

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

    // Just use the dark style with its pixel font
    GuiLoadStyleDark();
    GuiSetStyle(DEFAULT, TEXT_SIZE, 16);
    GuiSetStyle(DEFAULT, TEXT_SPACING, 1);

    Font customFont = { 0 };  // Not used, kept for cleanup code

    AppState state;

    while (!WindowShouldClose()) {
        float dt = GetFrameTime();
        state.toast.update(dt);

        int w = GetScreenWidth();
        int h = GetScreenHeight();

        // Reset raygui state each frame
        GuiUnlock();
        GuiSetState(STATE_NORMAL);

        // Check if any modal is open (to skip main UI interaction)
        bool modalOpen = state.show_license_modal || state.show_upgrade_modal || state.show_about_modal;

        BeginDrawing();
        ClearBackground(GetColor(0x1e1e1eff));

        // === Header ===
        int headerH = 54;
        DrawRectangle(0, 0, w, headerH, GetColor(0x252525ff));
        DrawLine(0, headerH, w, headerH, GetColor(0x3a3a3aff));

        DrawText("ImageTool Pro", 20, 17, 20, WHITE);
        DrawText("v1.0.0", 165, 22, 12, GRAY);

        // License badge (top right, compact)
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

        // Lock GUI if modal is open (so sidebar buttons don't respond)
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

        // Bottom buttons
        int bottomY = h - 28 - 90;
        if (GuiButton({(float)btnX, (float)bottomY, (float)btnW, 32},
                      state.licensed ? "Manage License" : "Activate License")) {
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

        // === Modals (unlock first so modal buttons work) ===
        GuiUnlock();
        DrawUpgradeModal(state);
        DrawLicenseModal(state);
        DrawAboutModal(state);

        // === Toast ===
        state.toast.draw(w, h);

        EndDrawing();
    }

    if (customFont.glyphCount > 0) UnloadFont(customFont);
    CloseWindow();
    return 0;
}
