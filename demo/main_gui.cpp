/**
 * SynthDemo - LicenseSeat C++ SDK Demo
 *
 * A compact audio synthesizer demo showcasing LicenseSeat SDK integration.
 * Audio generation based on raylib audio_raw_stream example.
 *
 * Free: Sine wave
 * Pro: Sawtooth, Square, Noise
 */

#include "raylib.h"

#define RAYGUI_IMPLEMENTATION
#include "raygui.h"

// Using default raygui style with dark colors

#include <licenseseat/licenseseat.hpp>
#include <licenseseat/events.hpp>

#include <string>
#include <cstring>
#include <memory>
#include <mutex>
#include <cmath>
#include <cstdlib>

#define TOOL_NAME "SynthDemo"
#define TOOL_VERSION "1.0.0"

// Audio constants
#define SAMPLE_RATE 44100
#define MAX_SAMPLES_PER_UPDATE 4096

// Wave types
enum WaveType { WAVE_SQUARE = 0, WAVE_SAWTOOTH, WAVE_SINE, WAVE_NOISE };

// Global synth state for audio callback
static struct {
    WaveType wave_type = WAVE_SINE;
    float frequency = 440.0f;
    float volume = 0.5f;
    bool playing = false;
    float phase = 0.0f;
    float noiseBuffer[32] = {0};
    std::mutex mtx;
} g_synth;

// Audio callback - called by raylib to fill audio buffer
void SynthCallback(void *buffer, unsigned int frames)
{
    std::lock_guard<std::mutex> lock(g_synth.mtx);

    short *d = (short *)buffer;
    float phaseInc = g_synth.frequency / (float)SAMPLE_RATE;

    for (unsigned int i = 0; i < frames; i++) {
        float sample = 0.0f;

        if (g_synth.playing) {
            float fp = g_synth.phase;

            switch (g_synth.wave_type) {
                case WAVE_SQUARE:
                    sample = (fp < 0.5f) ? 0.5f : -0.5f;
                    break;
                case WAVE_SAWTOOTH:
                    sample = 1.0f - fp * 2.0f;
                    break;
                case WAVE_SINE:
                    sample = sinf(fp * 2.0f * PI);
                    break;
                case WAVE_NOISE:
                    sample = g_synth.noiseBuffer[(int)(fp * 32) % 32];
                    break;
            }

            sample *= g_synth.volume;

            g_synth.phase += phaseInc;
            if (g_synth.phase >= 1.0f) {
                g_synth.phase -= 1.0f;
                // Refresh noise on cycle
                if (g_synth.wave_type == WAVE_NOISE) {
                    for (int j = 0; j < 32; j++) {
                        g_synth.noiseBuffer[j] = ((float)(rand() % 2001) - 1000) / 1000.0f;
                    }
                }
            }
        }

        d[i] = (short)(sample * 32000.0f);
    }
}

// Generate display waveform - shows more cycles at higher frequencies
void GenerateDisplayWaveform(float* waveform, int count) {
    // Show 1-8 cycles based on frequency (more cycles at higher freq)
    float cycles = 1.0f + (g_synth.frequency - 50.0f) / 300.0f;
    if (cycles > 8.0f) cycles = 8.0f;

    for (int i = 0; i < count; i++) {
        float fp = fmodf((float)i / count * cycles, 1.0f);
        float sample = 0.0f;

        switch (g_synth.wave_type) {
            case WAVE_SQUARE:
                sample = (fp < 0.5f) ? 0.5f : -0.5f;
                break;
            case WAVE_SAWTOOTH:
                sample = 1.0f - fp * 2.0f;
                break;
            case WAVE_SINE:
                sample = sinf(fp * 2.0f * PI);
                break;
            case WAVE_NOISE:
                sample = g_synth.noiseBuffer[(int)(fp * 32) % 32];
                break;
        }
        waveform[i] = sample * g_synth.volume;
    }
}

// Toast notification
struct Toast {
    std::string message;
    float timer = 0.0f;
    Color color = WHITE;
    bool active = false;

    void show(const char* msg, Color col = WHITE, float dur = 2.0f) {
        message = msg; color = col; timer = dur; active = true;
    }
    void update(float dt) { if (active && (timer -= dt) <= 0) active = false; }
    void draw(int w, int h) {
        if (!active) return;
        int tw = MeasureText(message.c_str(), 16);
        int bw = tw + 32, bh = 36;
        int x = (w - bw) / 2, y = h - 60;
        float a = (timer < 0.5f) ? timer * 2.0f : 1.0f;
        DrawRectangle(x, y, bw, bh, ColorAlpha(BLACK, 0.9f * a));
        DrawRectangleLinesEx({(float)x, (float)y, (float)bw, (float)bh}, 2, ColorAlpha(color, a));
        DrawText(message.c_str(), x + 16, y + 10, 16, ColorAlpha(color, a));
    }
};

// App state
struct AppState {
    std::unique_ptr<licenseseat::Client> sdk;
    Toast toast;

    bool licensed = false;
    std::string license_key;

    bool show_license_modal = false;
    bool show_about_modal = false;
    bool show_admin_modal = false;
    bool key_input_edit = false;
    bool activating = false;  // Async activation in progress
    char key_input[64] = "";
    std::string license_status;

    std::mutex toast_mutex;
    std::string pending_toast_msg;
    Color pending_toast_color = WHITE;
    bool has_pending_toast = false;

    void queue_toast(const std::string& msg, Color col = WHITE) {
        std::lock_guard<std::mutex> lock(toast_mutex);
        pending_toast_msg = msg;
        pending_toast_color = col;
        has_pending_toast = true;
    }

    void process_pending_toast() {
        std::lock_guard<std::mutex> lock(toast_mutex);
        if (has_pending_toast) {
            toast.show(pending_toast_msg.c_str(), pending_toast_color);
            has_pending_toast = false;
        }
    }

    void init_sdk() {
        licenseseat::Config config;
        config.api_key = "pk_test_9cXtKvf6rt2swMYJcg4ykiVyKFxFjWHri";
        config.product_slug = "synthdemo";
        config.api_url = "http://localhost:3000/api/v1";
        config.timeout_seconds = 3;
        config.verify_ssl = false;
        config.storage_path = "/tmp/synthdemo";
        config.app_version = TOOL_VERSION;

        // Fast intervals for demo
        config.auto_validate_interval = 10.0;    // 10 seconds
        config.network_recheck_interval = 5.0;   // 5 seconds
        config.heartbeat_interval = 10;          // 10 seconds

        sdk = std::make_unique<licenseseat::Client>(config);

        // Events
        sdk->on(licenseseat::events::LICENSE_REVOKED, [this](const std::any&) {
            licensed = false;
            {
                std::lock_guard<std::mutex> lock(g_synth.mtx);
                g_synth.wave_type = WAVE_SINE;
            }
            queue_toast("License revoked!", MAROON);
        });
        sdk->on(licenseseat::events::NETWORK_ONLINE, [this](const std::any&) {
            queue_toast("Online", GREEN);
        });
        sdk->on(licenseseat::events::NETWORK_OFFLINE, [this](const std::any&) {
            queue_toast("Offline", ORANGE);
        });
        sdk->on(licenseseat::events::SDK_RESET, [this](const std::any&) {
            licensed = false;
            {
                std::lock_guard<std::mutex> lock(g_synth.mtx);
                g_synth.wave_type = WAVE_SINE;
            }
        });
    }

    void restore_on_startup() {
        // Run restore async to avoid blocking startup
        sdk->restore_license_async([this](licenseseat::RestoreResult result) {
            if (result.status == licenseseat::ClientStatus::Active ||
                result.status == licenseseat::ClientStatus::OfflineValid) {
                licensed = true;
                if (result.license) {
                    license_key = result.license->key();
                    strncpy(key_input, license_key.c_str(), 63);
                }
                queue_toast(result.status == licenseseat::ClientStatus::Active ? "Pro activated" : "Offline mode",
                          result.status == licenseseat::ClientStatus::Active ? GREEN : ORANGE);
            }
        });
    }
};

void DrawWaveform(Rectangle bounds, Color color) {
    float waveform[256];
    GenerateDisplayWaveform(waveform, 256);

    DrawRectangleRec(bounds, GetColor(0x181818ff));
    DrawRectangleLinesEx(bounds, 2, GetColor(0x404040ff));

    float centerY = bounds.y + bounds.height / 2;
    DrawLine((int)bounds.x, (int)centerY, (int)(bounds.x + bounds.width), (int)centerY, GetColor(0x2a2a2aff));

    float stepX = bounds.width / 256.0f;
    float ampY = (bounds.height / 2.0f) * 0.85f;

    for (int i = 0; i < 255; i++) {
        float x1 = bounds.x + i * stepX;
        float y1 = centerY - waveform[i] * ampY;
        float x2 = bounds.x + (i + 1) * stepX;
        float y2 = centerY - waveform[i + 1] * ampY;
        DrawLineEx({x1, y1}, {x2, y2}, 2.0f, color);
    }
}

void DrawLicenseModal(AppState& state) {
    if (!state.show_license_modal) return;

    DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), ColorAlpha(BLACK, 0.85f));

    int w = 420, h = 200;
    int x = (GetScreenWidth() - w) / 2;
    int y = (GetScreenHeight() - h) / 2;

    DrawRectangle(x, y, w, h, GetColor(0x252525ff));
    DrawRectangleLinesEx({(float)x, (float)y, (float)w, (float)h}, 2, GetColor(0x555555ff));

    DrawText("Activate License", x + 24, y + 20, 22, WHITE);

    Rectangle inputBox = {(float)(x + 24), (float)(y + 60), (float)(w - 48), 36};
    if (GuiTextBox(inputBox, state.key_input, 64, state.key_input_edit)) {
        state.key_input_edit = !state.key_input_edit;
    }

    // Handle Cmd+V paste
    if (state.key_input_edit && (IsKeyDown(KEY_LEFT_SUPER) || IsKeyDown(KEY_RIGHT_SUPER)) && IsKeyPressed(KEY_V)) {
        const char* cb = GetClipboardText();
        if (cb) {
            strncpy(state.key_input, cb, 63);
            state.key_input[63] = '\0';
        }
    }

    if (!state.license_status.empty()) {
        DrawText(state.license_status.c_str(), x + 24, y + 108, 16, state.licensed ? GREEN : GRAY);
    }

    // Activate button - use async to avoid UI freeze
    if (state.activating) {
        GuiSetState(STATE_DISABLED);
        GuiButton({(float)(x + 24), (float)(y + h - 55), 90, 36}, "...");
        GuiSetState(STATE_NORMAL);
    } else if (GuiButton({(float)(x + 24), (float)(y + h - 55), 90, 36}, "Activate")) {
        std::string key(state.key_input);
        if (!key.empty() && state.sdk) {
            state.activating = true;
            state.license_status = "Activating...";

            // Run activation async
            state.sdk->activate_async(key, [&state, key](licenseseat::Result<licenseseat::Activation> result) {
                bool ok = result.is_ok() || result.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated;
                if (ok) {
                    // Validate async too
                    state.sdk->validate_async(key, [&state, key](licenseseat::Result<licenseseat::ValidationResult> val) {
                        if (val.is_ok()) {
                            state.licensed = true;
                            state.license_key = key;
                            state.license_status = "Activated!";
                            state.queue_toast("Pro unlocked!", GREEN);
                            state.sdk->start_heartbeat(key);
                            state.sdk->start_auto_validation(key);
                            // Close license window on success
                            state.show_license_modal = false;
                            state.key_input_edit = false;
                        } else {
                            state.license_status = val.error_message();
                        }
                        state.activating = false;
                    });
                } else {
                    state.license_status = result.error_message();
                    state.activating = false;
                }
            });
        }
    }

    if (GuiButton({(float)(x + 124), (float)(y + h - 55), 100, 36}, "Deactivate")) {
        if (state.sdk) state.sdk->reset();
        state.licensed = false;
        state.license_key.clear();
        state.license_status = "Deactivated";
        {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.wave_type = WAVE_SINE;
        }
        memset(state.key_input, 0, sizeof(state.key_input));
    }

    if (GuiButton({(float)(x + w - 80), (float)(y + h - 55), 60, 36}, "Close")) {
        state.show_license_modal = false;
        state.key_input_edit = false;
    }
}

void DrawAdminModal(AppState& state) {
    if (!state.show_admin_modal) return;

    DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), ColorAlpha(BLACK, 0.85f));

    int w = 700, h = 340;
    int x = (GetScreenWidth() - w) / 2;
    int y = (GetScreenHeight() - h) / 2;

    DrawRectangle(x, y, w, h, GetColor(0x252525ff));
    DrawRectangleLinesEx({(float)x, (float)y, (float)w, (float)h}, 2, GetColor(0x555555ff));

    DrawText("SDK Admin", x + 24, y + 18, 20, WHITE);

    // Three columns
    int col1X = x + 24;
    int col1ValX = x + 105;
    int col2X = x + 235;
    int col2ValX = x + 330;
    int col3X = x + 460;
    int col3ValX = x + 540;
    int row = y + 48;

    // === Column 1: Config ===
    DrawText("CONFIG", col1X, row, 11, GOLD);
    row += 16;

    DrawText("API:", col1X, row, 12, LIGHTGRAY);
    DrawText("localhost:3000", col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("Product:", col1X, row, 12, LIGHTGRAY);
    DrawText("synthdemo", col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("API Key:", col1X, row, 12, LIGHTGRAY);
    DrawText("pk_test_9c...", col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("Storage:", col1X, row, 12, LIGHTGRAY);
    DrawText("/tmp/synthd...", col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("Timeout:", col1X, row, 12, LIGHTGRAY);
    DrawText("3s", col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("SSL:", col1X, row, 12, LIGHTGRAY);
    DrawText("No", col1ValX, row, 12, ORANGE);

    // === Column 2: Runtime ===
    row = y + 48;
    DrawText("RUNTIME", col2X, row, 11, GOLD);
    row += 16;

    auto status = state.sdk->get_client_status();
    DrawText("Status:", col2X, row, 12, LIGHTGRAY);
    Color statusCol = GRAY;
    if (status == licenseseat::ClientStatus::Active) statusCol = GREEN;
    else if (status == licenseseat::ClientStatus::OfflineValid) statusCol = ORANGE;
    else if (status == licenseseat::ClientStatus::Invalid) statusCol = MAROON;
    DrawText(licenseseat::client_status_to_string(status), col2ValX, row, 12, statusCol);
    row += 15;

    bool online = state.sdk->is_online();
    DrawText("Network:", col2X, row, 12, LIGHTGRAY);
    DrawText(online ? "Online" : "Offline", col2ValX, row, 12, online ? GREEN : ORANGE);
    row += 15;

    bool hb = state.sdk->is_heartbeat_running();
    DrawText("Heartbeat:", col2X, row, 12, LIGHTGRAY);
    DrawText(hb ? "Running" : "Stopped", col2ValX, row, 12, hb ? GREEN : GRAY);
    row += 15;

    bool av = state.sdk->is_auto_validating();
    DrawText("Auto-Valid:", col2X, row, 12, LIGHTGRAY);
    DrawText(av ? "Running" : "Stopped", col2ValX, row, 12, av ? GREEN : GRAY);
    row += 15;

    auto valResult = state.sdk->get_status();
    DrawText("Cached:", col2X, row, 12, LIGHTGRAY);
    DrawText(valResult.valid ? "Valid" : "Invalid", col2ValX, row, 12, valResult.valid ? GREEN : GRAY);
    row += 15;

    DrawText("Offline:", col2X, row, 12, LIGHTGRAY);
    DrawText(valResult.offline ? "Yes" : "No", col2ValX, row, 12, valResult.offline ? ORANGE : GRAY);

    // === Column 3: License Info ===
    row = y + 48;
    DrawText("LICENSE", col3X, row, 11, GOLD);
    row += 16;

    if (valResult.valid) {
        const auto& lic = valResult.license;

        DrawText("Key:", col3X, row, 12, LIGHTGRAY);
        std::string keyShort = lic.key().length() > 10 ? lic.key().substr(0, 10) + "..." : lic.key();
        DrawText(keyShort.c_str(), col3ValX, row, 12, WHITE);
        row += 15;

        DrawText("Plan:", col3X, row, 12, LIGHTGRAY);
        DrawText(lic.plan_key().c_str(), col3ValX, row, 12, WHITE);
        row += 15;

        DrawText("Seats:", col3X, row, 12, LIGHTGRAY);
        if (lic.seat_limit().has_value()) {
            DrawText(TextFormat("%d/%d", lic.active_seats(), lic.seat_limit().value()), col3ValX, row, 12, WHITE);
        } else {
            DrawText(TextFormat("%d/∞", lic.active_seats()), col3ValX, row, 12, WHITE);
        }
        row += 15;

        DrawText("Expires:", col3X, row, 12, LIGHTGRAY);
        if (lic.expires_at().has_value()) {
            auto exp = lic.expires_at().value();
            auto now = std::chrono::system_clock::now();
            auto diff = std::chrono::duration_cast<std::chrono::hours>(exp - now).count();
            if (diff > 24) {
                DrawText(TextFormat("%dd", (int)(diff / 24)), col3ValX, row, 12, WHITE);
            } else if (diff > 0) {
                DrawText(TextFormat("%dh", (int)diff), col3ValX, row, 12, ORANGE);
            } else {
                DrawText("Expired", col3ValX, row, 12, MAROON);
            }
        } else {
            DrawText("Never", col3ValX, row, 12, GREEN);
        }
        row += 15;

        // Entitlements
        DrawText("Entitle:", col3X, row, 12, LIGHTGRAY);
        const auto& ents = lic.active_entitlements();
        if (ents.empty()) {
            DrawText("(none)", col3ValX, row, 12, GRAY);
        } else {
            std::string entStr;
            for (size_t i = 0; i < ents.size() && i < 3; i++) {
                if (i > 0) entStr += ", ";
                entStr += ents[i].key;
            }
            if (ents.size() > 3) entStr += "...";
            DrawText(entStr.c_str(), col3ValX, row, 12, WHITE);
        }
    } else {
        DrawText("(no license)", col3X, row + 30, 12, GRAY);
    }

    // Separator
    int sepY = y + 158;
    DrawLine(x + 24, sepY, x + w - 24, sepY, GetColor(0x404040ff));

    // Bottom section - compact three columns
    int detailY = sepY + 10;
    int col1 = x + 24;
    int col2 = x + 260;
    int col3 = x + 480;

    // Column 1: License Key
    DrawText("KEY", col1, detailY, 10, GOLD);
    detailY += 12;
    if (!state.license_key.empty()) {
        DrawText(state.license_key.c_str(), col1, detailY, 10, WHITE);
    } else {
        DrawText("(none)", col1, detailY, 10, GRAY);
    }

    // Column 2: Entitlements
    int entY = sepY + 10;
    DrawText("ENTITLEMENTS", col2, entY, 10, GOLD);
    entY += 12;
    if (valResult.valid && !valResult.license.active_entitlements().empty()) {
        std::string entStr;
        for (size_t i = 0; i < valResult.license.active_entitlements().size(); i++) {
            if (i > 0) entStr += ", ";
            entStr += valResult.license.active_entitlements()[i].key;
        }
        DrawText(entStr.c_str(), col2, entY, 10, WHITE);
    } else {
        DrawText("(none)", col2, entY, 10, GRAY);
    }

    // Column 3: Metadata (compact)
    int metaY = sepY + 10;
    DrawText("METADATA", col3, metaY, 10, GOLD);
    metaY += 12;
    if (valResult.valid && !valResult.license.metadata().empty()) {
        int count = 0;
        for (const auto& [k, v] : valResult.license.metadata()) {
            if (count >= 4) { DrawText("...", col3, metaY, 10, GRAY); break; }
            std::string kv = k + "=" + (v.length() > 12 ? v.substr(0,12) + ".." : v);
            DrawText(kv.c_str(), col3, metaY, 10, WHITE);
            metaY += 11;
            count++;
        }
    } else {
        DrawText("(none)", col3, metaY, 10, GRAY);
    }

    // Bottom buttons
    int btnY = y + h - 50;

    if (GuiButton({(float)(x + 24), (float)btnY, 130, 32}, "Clear All Data")) {
        if (state.sdk) state.sdk->reset();
        state.licensed = false;
        state.license_key.clear();
        state.license_status.clear();
        {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.wave_type = WAVE_SINE;
        }
        memset(state.key_input, 0, sizeof(state.key_input));
        state.toast.show("All data cleared", ORANGE);
    }

    if (GuiButton({(float)(x + w - 75), (float)btnY, 55, 32}, "Close")) {
        state.show_admin_modal = false;
    }
}

void DrawAboutModal(AppState& state) {
    if (!state.show_about_modal) return;

    DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), ColorAlpha(BLACK, 0.85f));

    int w = 400, h = 200;
    int x = (GetScreenWidth() - w) / 2;
    int y = (GetScreenHeight() - h) / 2;

    DrawRectangle(x, y, w, h, GetColor(0x252525ff));
    DrawRectangleLinesEx({(float)x, (float)y, (float)w, (float)h}, 2, GetColor(0x555555ff));

    DrawText(TOOL_NAME, x + 24, y + 22, 26, WHITE);
    DrawText(TextFormat("v%s", TOOL_VERSION), x + 170, y + 28, 16, GRAY);
    DrawText("LicenseSeat SDK Demo", x + 24, y + 75, 18, LIGHTGRAY);

    // Clickable link
    Rectangle linkRect = {(float)(x + 24), (float)(y + 110), 140, 20};
    DrawText("licenseseat.com", x + 24, y + 110, 16, SKYBLUE);
    if (CheckCollisionPointRec(GetMousePosition(), linkRect)) {
        DrawLine(x + 24, y + 126, x + 24 + 130, y + 126, SKYBLUE);
        if (IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
            OpenURL("https://licenseseat.com");
        }
    }

    if (GuiButton({(float)(x + w - 80), (float)(y + h - 52), 60, 36}, "Close")) {
        state.show_about_modal = false;
    }
}

int main() {
    const int screenWidth = 720;
    const int screenHeight = 380;

    SetConfigFlags(FLAG_VSYNC_HINT);
    InitWindow(screenWidth, screenHeight, TextFormat("%s v%s", TOOL_NAME, TOOL_VERSION));
    SetTargetFPS(60);

    // Initialize audio
    InitAudioDevice();
    SetAudioStreamBufferSizeDefault(MAX_SAMPLES_PER_UPDATE);
    AudioStream stream = LoadAudioStream(SAMPLE_RATE, 16, 1);
    SetAudioStreamCallback(stream, SynthCallback);
    PlayAudioStream(stream);

    // Initialize noise buffer
    for (int i = 0; i < 32; i++) {
        g_synth.noiseBuffer[i] = ((float)(rand() % 2001) - 1000) / 1000.0f;
    }

    // Setup GUI style - dark colors, default font
    GuiSetStyle(DEFAULT, BORDER_COLOR_NORMAL, 0x606060ff);
    GuiSetStyle(DEFAULT, BASE_COLOR_NORMAL, 0x404040ff);
    GuiSetStyle(DEFAULT, TEXT_COLOR_NORMAL, 0xd0d0d0ff);
    GuiSetStyle(DEFAULT, BORDER_COLOR_FOCUSED, 0x808080ff);
    GuiSetStyle(DEFAULT, BASE_COLOR_FOCUSED, 0x505050ff);
    GuiSetStyle(DEFAULT, TEXT_COLOR_FOCUSED, 0xffffffff);
    GuiSetStyle(DEFAULT, BORDER_COLOR_PRESSED, 0x909090ff);
    GuiSetStyle(DEFAULT, BASE_COLOR_PRESSED, 0x606060ff);
    GuiSetStyle(DEFAULT, TEXT_COLOR_PRESSED, 0xffffffff);
    GuiSetStyle(DEFAULT, BORDER_COLOR_DISABLED, 0x404040ff);
    GuiSetStyle(DEFAULT, BASE_COLOR_DISABLED, 0x303030ff);
    GuiSetStyle(DEFAULT, TEXT_COLOR_DISABLED, 0x707070ff);
    GuiSetStyle(DEFAULT, TEXT_SIZE, 16);
    GuiSetStyle(DEFAULT, BACKGROUND_COLOR, 0x1a1a1aff);

    AppState state;
    state.init_sdk();
    state.restore_on_startup();

    while (!WindowShouldClose()) {
        float dt = GetFrameTime();
        state.toast.update(dt);
        state.process_pending_toast();

        int w = GetScreenWidth();
        int h = GetScreenHeight();

        bool modalOpen = state.show_license_modal || state.show_about_modal || state.show_admin_modal;
        if (modalOpen) GuiLock(); else GuiUnlock();

        BeginDrawing();
        ClearBackground(GetColor(0x1a1a1aff));

        // === Header ===
        DrawRectangle(0, 0, w, 52, GetColor(0x222222ff));
        DrawLine(0, 52, w, 52, GetColor(0x3a3a3aff));

        DrawText(TOOL_NAME, 16, 14, 24, WHITE);
        DrawText(TextFormat("v%s", TOOL_VERSION), 150, 18, 16, GRAY);

        // License badge
        {
            int bx = w - 130;
            Color bc = state.licensed ? GREEN : GRAY;
            const char* bt = state.licensed ? "PRO" : "FREE";
            DrawRectangle(bx, 10, 80, 32, ColorAlpha(bc, 0.2f));
            DrawRectangleLinesEx({(float)bx, 10, 80, 32}, 2, bc);
            DrawText(bt, bx + (state.licensed ? 22 : 16), 17, 18, bc);
        }

        // SDK status dot
        {
            auto st = state.sdk->get_client_status();
            Color sc = GRAY;
            if (st == licenseseat::ClientStatus::Active) sc = GREEN;
            else if (st == licenseseat::ClientStatus::OfflineValid) sc = ORANGE;
            else if (st == licenseseat::ClientStatus::Invalid) sc = MAROON;
            DrawCircle(w - 35, 26, 8, sc);
        }

        // === Waveform ===
        int contentY = 62;
        Rectangle waveRect = {16, (float)contentY, (float)(w - 32), 120};
        Color waveCol = state.licensed ? SKYBLUE : GetColor(0x5a9a5aff);
        if (g_synth.playing) waveCol = state.licensed ? GREEN : GetColor(0x7aba7aff);
        DrawWaveform(waveRect, waveCol);

        // Wave name & frequency
        const char* waveNames[] = {"Square", "Sawtooth", "Sine", "Noise"};
        DrawText(waveNames[g_synth.wave_type], 28, contentY + 12, 20, ColorAlpha(WHITE, 0.9f));
        DrawText(TextFormat("%.0f Hz", g_synth.frequency), w - 110, contentY + 12, 18, GRAY);

        // === Controls ===
        int ctrlY = contentY + 132;
        int btnW = 100, btnH = 36, gap = 10;
        int x = 16;

        // Play/Stop
        Color playBtnCol = g_synth.playing ? GetColor(0x3a6a3aff) : GetColor(0x2a2a2aff);
        DrawRectangle(x, ctrlY, 70, btnH, playBtnCol);
        if (GuiButton({(float)x, (float)ctrlY, 70, (float)btnH}, g_synth.playing ? "Stop" : "Play")) {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.playing = !g_synth.playing;
        }
        x += 80;

        // Sine (FREE)
        bool sineActive = g_synth.wave_type == WAVE_SINE;
        if (sineActive) DrawRectangle(x, ctrlY, 90, btnH, ColorAlpha(GREEN, 0.25f));
        if (GuiButton({(float)x, (float)ctrlY, 90, (float)btnH}, "Sine")) {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.wave_type = WAVE_SINE;
        }
        x += 100;

        // PRO buttons
        auto drawProBtn = [&](const char* label, WaveType type) {
            bool active = g_synth.wave_type == type;
            if (state.licensed) {
                if (active) DrawRectangle(x, ctrlY, 90, btnH, ColorAlpha(GOLD, 0.25f));
                if (GuiButton({(float)x, (float)ctrlY, 90, (float)btnH}, label)) {
                    std::lock_guard<std::mutex> lock(g_synth.mtx);
                    g_synth.wave_type = type;
                }
            } else {
                // Use GuiButton but disabled, then draw PRO badge on top
                GuiSetState(STATE_DISABLED);
                GuiButton({(float)x, (float)ctrlY, 90, (float)btnH}, label);
                GuiSetState(STATE_NORMAL);
                DrawText("PRO", x + 90 - 25, ctrlY + 24, 10, GOLD);
                if (CheckCollisionPointRec(GetMousePosition(), {(float)x, (float)ctrlY, 90, (float)btnH}) &&
                    IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
                    state.show_license_modal = true;
                }
            }
            x += 100;
        };

        drawProBtn("Sawtooth", WAVE_SAWTOOTH);
        drawProBtn("Square", WAVE_SQUARE);
        drawProBtn("Noise", WAVE_NOISE);

        // === Sliders ===
        int sliderY = ctrlY + 52;

        DrawText("Freq", 16, sliderY + 8, 18, LIGHTGRAY);
        float fv = g_synth.frequency;
        GuiSlider({70, (float)sliderY, 240, 32}, NULL, TextFormat("%.0f Hz", fv), &fv, 50.0f, 2000.0f);
        {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.frequency = fv;
        }

        DrawText("Vol", 420, sliderY + 8, 18, LIGHTGRAY);
        float vv = g_synth.volume;
        GuiSlider({470, (float)sliderY, 180, 32}, NULL, TextFormat("%.0f%%", vv * 100), &vv, 0.0f, 1.0f);
        {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.volume = vv;
        }

        // === Bottom bar ===
        int bottomY = h - 48;
        DrawRectangle(0, bottomY, w, 48, GetColor(0x1e1e1eff));
        DrawLine(0, bottomY, w, bottomY, GetColor(0x3a3a3aff));

        if (GuiButton({16, (float)(bottomY + 6), 90, 36}, state.licensed ? "License" : "Activate")) {
            if (!state.license_key.empty()) strncpy(state.key_input, state.license_key.c_str(), 63);
            state.show_license_modal = true;
        }

        if (GuiButton({116, (float)(bottomY + 6), 70, 36}, "About")) {
            state.show_about_modal = true;
        }

        if (GuiButton({196, (float)(bottomY + 6), 70, 36}, "Admin")) {
            state.show_admin_modal = true;
        }

        const char* statusTxt = state.licensed ? "Pro License Active" : "Free Version";
        DrawText(statusTxt, w - MeasureText(statusTxt, 16) - 16, bottomY + 16, 16, GRAY);

        // === Modals ===
        GuiUnlock();
        DrawLicenseModal(state);
        DrawAboutModal(state);
        DrawAdminModal(state);
        state.toast.draw(w, h);

        EndDrawing();
    }

    StopAudioStream(stream);
    UnloadAudioStream(stream);
    CloseAudioDevice();
    CloseWindow();
    return 0;
}
