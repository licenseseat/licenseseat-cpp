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

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
// WASM Demo Mode - Mock validation with Stripe-style test keys
// 4242-4242-4242-4242  → Valid Pro license
// 4000-0000-0000-0002  → Invalid key
// 4000-0000-0000-0010  → Expired license
// 4000-0000-0000-0020  → Suspended license
// 4000-0000-0000-0069  → Seat limit exceeded
#define WASM_DEMO_MODE 1
#else
#include <licenseseat/licenseseat.hpp>
#include <licenseseat/events.hpp>
#include <licenseseat/json.hpp>
#define WASM_DEMO_MODE 0
#endif

#include <algorithm>
#include <any>
#include <string>
#include <map>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <cmath>
#include <cstdlib>
#include <cctype>
#include <optional>

#define TOOL_NAME "SynthDemo"
#define TOOL_VERSION "1.0.0"
#define DEMO_STORAGE_PATH "/tmp/synthdemo"

static std::string ShortenMiddle(const std::string& value, size_t max_len) {
    if (value.size() <= max_len) return value;
    size_t head = max_len / 2;
    size_t tail = max_len > head + 2 ? max_len - head - 2 : 0;
    return value.substr(0, head) + ".." + value.substr(value.size() - tail);
}

static std::string EventField(const std::any& payload, const std::string& key) {
    const auto* values = std::any_cast<std::map<std::string, std::string>>(&payload);
    if (!values) return {};

    auto it = values->find(key);
    if (it == values->end()) return {};
    return it->second;
}

static std::string Lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

static bool LooksLikePermissionError(const std::string& error) {
    auto normalized = Lowercase(error);
    return normalized.find("403") != std::string::npos ||
           normalized.find("forbidden") != std::string::npos ||
           normalized.find("scope") != std::string::npos ||
           normalized.find("permission") != std::string::npos ||
           normalized.find("authorized") != std::string::npos;
}

static Color CacheBadgeColor(const std::string& status, Color cached_color) {
    if (status == "Cached") return cached_color;
    if (status == "Syncing") return GOLD;
    if (status == "Denied") return ORANGE;
    if (status == "Failed" || status == "Invalid") return MAROON;
    return GRAY;
}

static std::optional<std::string> EnvValue(const char* name) {
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0') return std::nullopt;
    return std::string(value);
}

static std::string EnvOr(const char* name, const std::string& fallback) {
    auto value = EnvValue(name);
    return value.has_value() ? *value : fallback;
}

static int EnvIntOr(const char* name, int fallback) {
    auto value = EnvValue(name);
    if (!value.has_value()) return fallback;

    try {
        return std::stoi(*value);
    } catch (...) {
        return fallback;
    }
}

static bool EnvBoolOr(const char* name, bool fallback) {
    auto value = EnvValue(name);
    if (!value.has_value()) return fallback;

    auto normalized = Lowercase(*value);
    if (normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on") {
        return true;
    }
    if (normalized == "0" || normalized == "false" || normalized == "no" || normalized == "off") {
        return false;
    }

    return fallback;
}

static std::string FormatUnixTime(int64_t ts) {
    if (ts == 0) return "-";
    time_t t = static_cast<time_t>(ts);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%b %d, %Y %H:%M", std::gmtime(&t));
    return buf;
}

static std::string ApiEndpointHost(const std::string& api_url) {
    auto scheme_pos = api_url.find("://");
    size_t host_start = scheme_pos == std::string::npos ? 0 : scheme_pos + 3;
    auto path_pos = api_url.find('/', host_start);
    return api_url.substr(host_start, path_pos == std::string::npos ? std::string::npos
                                                                    : path_pos - host_start);
}

// Simple JSON string value extraction (no dependencies)
static std::string JsonStringValue(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

static int64_t JsonIntValue(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return 0;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return 0;
    while (pos < json.size() && (json[pos] == ':' || json[pos] == ' ')) pos++;
    if (pos >= json.size() || (!isdigit(json[pos]) && json[pos] != '-')) return 0;
    return std::stoll(json.substr(pos));
}

#if !WASM_DEMO_MODE
struct MachineFileInfo {
    bool loaded = false;
    bool verified = false;
    // Envelope fields
    std::string algorithm;
    int64_t ttl = 0;
    std::string issued;
    std::string expiry;
    std::string license_key;
    std::string fingerprint;
    std::string certificate_preview;
    // Decrypted payload fields
    int64_t iat = 0;
    int64_t exp = 0;
    int64_t nbf = 0;
    int64_t payload_ttl = 0;
    int64_t grace_period = 0;
    std::string machine_id;
    std::string device_name;
    std::string platform;
    std::string key_id;
    std::map<std::string, std::string> metadata;
    std::vector<licenseseat::Entitlement> entitlements;
};

static MachineFileInfo LoadMachineFileInfo(const std::string& storage_path, licenseseat::Client* sdk) {
    MachineFileInfo info;
    auto path = std::filesystem::path(storage_path) / "licenseseat_machine_file.json";
    if (!std::filesystem::exists(path)) return info;

    std::ifstream file(path);
    if (!file.is_open()) return info;

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    try {
        auto j = nlohmann::json::parse(content);
        info.loaded = true;

        // Parse flat JSON structure (stored format)
        info.algorithm = j.value("algorithm", "");
        info.ttl = j.value("ttl", int64_t{0});
        info.license_key = j.value("license_key", "");
        info.fingerprint = j.value("fingerprint", "");
        info.issued = j.value("issued_at", "");
        info.expiry = j.value("expires_at", "");

        // Certificate preview
        std::string cert = j.value("certificate", "");
        if (!cert.empty()) {
            auto start = cert.find('\n');
            if (start != std::string::npos) start++;
            else start = 0;
            info.certificate_preview = cert.substr(start, std::min(size_t(50), cert.size() - start));
            if (cert.size() > start + 50) info.certificate_preview += "...";
        }

        // Build MachineFile struct for verification
        licenseseat::MachineFile mf;
        mf.certificate = cert;
        mf.algorithm = info.algorithm;
        mf.ttl = info.ttl;
        mf.license_key = info.license_key;
        mf.fingerprint = info.fingerprint;

        // Verify to get decrypted payload
        if (sdk && !cert.empty()) {
            auto result = sdk->verify_machine_file(mf);
            if (result.is_ok() && result.value().payload) {
                info.verified = true;
                auto& p = *result.value().payload;
                info.iat = p.iat;
                info.exp = p.exp;
                info.nbf = p.nbf;
                info.payload_ttl = p.ttl;
                info.grace_period = p.grace_period;
                info.machine_id = p.machine_id;
                info.device_name = p.device_name;
                info.platform = p.platform;
                info.key_id = p.key_id;
                info.metadata = p.metadata;
                if (p.license) {
                    info.entitlements = p.license->active_entitlements();
                }
            }
        }
    } catch (...) {
        info.loaded = false;
    }

    return info;
}

static std::string ApiEndpointPath(const std::string& api_url) {
    auto scheme_pos = api_url.find("://");
    size_t host_start = scheme_pos == std::string::npos ? 0 : scheme_pos + 3;
    auto path_pos = api_url.find('/', host_start);
    return path_pos == std::string::npos ? "/" : api_url.substr(path_pos);
}
#endif  // !WASM_DEMO_MODE

// Audio constants
#define SAMPLE_RATE 44100
#define MAX_SAMPLES_PER_UPDATE 4096

// Wave types
enum WaveType { WAVE_SQUARE = 0, WAVE_SAWTOOTH, WAVE_SINE, WAVE_NOISE };

// Global synth state for audio callback
static struct {
    WaveType wave_type = WAVE_SINE;
    float frequency = 440.0f;
    float volume = 0.25f;
    bool playing = false;
    float phase = 0.0f;
    float envelope = 1.0f;  // Attack envelope (0->1)
    float noiseBuffer[32] = {0};
    bool snap_to_note = false;
    int octave = 4;  // Base octave for piano keys (C4 = middle C)
    std::mutex mtx;
} g_synth;

// Snap frequency to nearest semitone
float SnapToNote(float freq) {
    float semitone = 12.0f * log2f(freq / 440.0f) + 69.0f;
    int nearest = (int)roundf(semitone);
    return 440.0f * powf(2.0f, (nearest - 69.0f) / 12.0f);
}

// Convert frequency to musical note name with cents deviation
std::string FreqToNote(float freq) {
    static const char* noteNames[] = {"C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"};

    // A4 = 440 Hz, MIDI note 69
    float semitones = 12.0f * log2f(freq / 440.0f) + 69.0f;
    int nearestNote = (int)roundf(semitones);
    float cents = (semitones - nearestNote) * 100.0f;

    int octave = (nearestNote / 12) - 1;
    int noteIndex = nearestNote % 12;
    if (noteIndex < 0) { noteIndex += 12; octave--; }

    char buf[32];
    if (fabsf(cents) < 1.0f) {
        snprintf(buf, sizeof(buf), "%s%d", noteNames[noteIndex], octave);
    } else {
        snprintf(buf, sizeof(buf), "%s%d %+.0fc", noteNames[noteIndex], octave, cents);
    }
    return std::string(buf);
}

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

            sample *= g_synth.volume * g_synth.envelope;

            // Ramp envelope up (attack ~5ms)
            if (g_synth.envelope < 1.0f) {
                g_synth.envelope += 1.0f / (SAMPLE_RATE * 0.005f);  // 5ms attack
                if (g_synth.envelope > 1.0f) g_synth.envelope = 1.0f;
            }

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
// Animation phase for waveform display
static float g_wavePhase = 0.0f;

void GenerateDisplayWaveform(float* waveform, int count, float dt) {
    // Log scale for cycles: 2 cycles at 100Hz, ~4 at 1kHz, ~6 at 9kHz
    // Allow fractional cycles below 50Hz for visual distinction
    float cycles = 2.0f + log2f(g_synth.frequency / 100.0f);
    if (cycles < 0.25f) cycles = 0.25f;  // Min ~quarter cycle at very low freq
    if (cycles > 8.0f) cycles = 8.0f;

    // Animate phase when playing
    if (g_synth.playing) {
        g_wavePhase += dt * 3.0f;  // Speed of animation
        if (g_wavePhase > 1.0f) g_wavePhase -= 1.0f;
    }

    for (int i = 0; i < count; i++) {
        float fp = fmodf((float)i / count * cycles + g_wavePhase, 1.0f);
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

// WASM Demo Mode - Mock validation with Stripe-style test keys
#if WASM_DEMO_MODE
struct MockValidationResult {
    bool valid = false;
    std::string error_code;
    std::string error_message;
};

static MockValidationResult MockValidate(const std::string& key) {
    MockValidationResult result;
    if (key == "4242-4242-4242-4242") {
        result.valid = true;
    } else if (key == "4000-0000-0000-0002") {
        result.error_code = "INVALID_KEY";
        result.error_message = "License key not found";
    } else if (key == "4000-0000-0000-0010") {
        result.error_code = "LICENSE_EXPIRED";
        result.error_message = "License has expired";
    } else if (key == "4000-0000-0000-0020") {
        result.error_code = "LICENSE_SUSPENDED";
        result.error_message = "License is suspended";
    } else if (key == "4000-0000-0000-0069") {
        result.error_code = "SEAT_LIMIT_EXCEEDED";
        result.error_message = "No seats available";
    } else {
        result.error_code = "INVALID_KEY";
        result.error_message = "Invalid license key";
    }
    return result;
}

extern "C" {
EMSCRIPTEN_KEEPALIVE
void ResizeEmbeddedDemo(int width, int height) {
    if (width <= 0 || height <= 0) return;
    SetWindowSize(width, height);
}
}
#endif

// App state
struct AppState {
#if !WASM_DEMO_MODE
    std::unique_ptr<licenseseat::Client> sdk;
    licenseseat::Config sdk_config;
#endif
    Toast toast;

    bool licensed = false;
    std::string license_key;

    bool show_license_modal = false;
    bool show_about_modal = false;
    bool show_help_modal = false;
#if !WASM_DEMO_MODE
    bool show_machine_file_modal = false;
    bool show_admin_modal = false;
#endif
    bool key_input_edit = false;
    bool activating = false;
    bool deactivating = false;
    char key_input[64] = "";
    std::string license_status;
#if !WASM_DEMO_MODE
    std::string machine_file_status;
    std::string offline_token_status;
    std::string offline_cache_status;
    bool machine_file_cached = false;
    bool offline_token_cached = false;
    bool legacy_offline_tokens_enabled = false;

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
#endif

    void refresh_cache_status() {
#if !WASM_DEMO_MODE
        auto storage_root = sdk_config.storage_path.empty() ? std::string(DEMO_STORAGE_PATH)
                                                            : sdk_config.storage_path;
        machine_file_cached = std::filesystem::exists(
            std::filesystem::path(storage_root) / "licenseseat_machine_file.json");
        offline_token_cached = std::filesystem::exists(
            std::filesystem::path(storage_root) / "licenseseat_offline_token.json");

        if (machine_file_cached) {
            machine_file_status = "Cached";
        } else if (machine_file_status.empty() || machine_file_status == "Cached") {
            machine_file_status = "Missing";
        }

        if (offline_token_cached) {
            offline_token_status = "Cached";
        } else if (legacy_offline_tokens_enabled &&
                   (offline_token_status.empty() || offline_token_status == "Cached")) {
            offline_token_status = "Missing";
        } else if (!legacy_offline_tokens_enabled) {
            offline_token_status.clear();
        }

        if (offline_cache_status.empty()) {
            if (machine_file_cached) {
                offline_cache_status = "Machine file cached";
            } else if (offline_token_cached) {
                offline_cache_status = "Offline token cached";
            }
        }
#endif
    }

    void init_sdk() {
#if WASM_DEMO_MODE
        // No SDK init in WASM demo mode
#else
        licenseseat::Config config;
        config.api_key = EnvOr("LICENSESEAT_API_KEY", "pk_test_9cXtKvf6rt2swMYJcg4ykiVyKFxFjWHri");
        config.product_slug = EnvOr("LICENSESEAT_PRODUCT_SLUG", "synthdemo");
        config.api_url = EnvOr("LICENSESEAT_API_URL", "https://licenseseat.com/api/v1");
        config.timeout_seconds = EnvIntOr("LICENSESEAT_TIMEOUT_SECONDS", 3);
        config.verify_ssl = EnvBoolOr("LICENSESEAT_VERIFY_SSL", false);
        config.storage_path = EnvOr("LICENSESEAT_STORAGE_PATH", DEMO_STORAGE_PATH);
        config.enable_legacy_offline_tokens =
            EnvBoolOr("LICENSESEAT_ENABLE_LEGACY_OFFLINE_TOKENS", false);
        config.app_version = TOOL_VERSION;

        // Fast intervals for demo
        config.auto_validate_interval = 10.0;    // 10 seconds
        config.network_recheck_interval = 5.0;   // 5 seconds
        config.heartbeat_interval = 10;          // 10 seconds

        sdk_config = config;
        legacy_offline_tokens_enabled = config.enable_legacy_offline_tokens;
        sdk = std::make_unique<licenseseat::Client>(config);
        refresh_cache_status();

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
            machine_file_status.clear();
            offline_token_status.clear();
            offline_cache_status.clear();
            refresh_cache_status();
            {
                std::lock_guard<std::mutex> lock(g_synth.mtx);
                g_synth.wave_type = WAVE_SINE;
            }
        });
        sdk->on(licenseseat::events::MACHINE_FILE_FETCHING, [this](const std::any&) {
            machine_file_status = "Syncing";
            offline_cache_status = "Requesting machine file...";
        });
        sdk->on(licenseseat::events::MACHINE_FILE_READY, [this](const std::any&) {
            machine_file_status = "Cached";
            offline_cache_status = "Machine file cached";
            refresh_cache_status();
            queue_toast("Machine file ready", SKYBLUE);
        });
        sdk->on(licenseseat::events::MACHINE_FILE_FETCH_ERROR, [this](const std::any& payload) {
            auto error = EventField(payload, "error");
            bool permission_error = LooksLikePermissionError(error);
            machine_file_status = permission_error ? "Denied" : "Failed";
            offline_cache_status = legacy_offline_tokens_enabled
                ? (permission_error
                       ? "Machine file denied; legacy token fallback enabled"
                       : "Machine file failed; legacy token fallback enabled")
                : (permission_error ? "Machine file denied" : "Machine file failed");
            queue_toast(permission_error ? "Machine file denied: check API key scopes"
                                         : "Machine file sync failed",
                        permission_error ? ORANGE : MAROON);
            refresh_cache_status();
        });
        sdk->on(licenseseat::events::MACHINE_FILE_VERIFICATION_FAILED, [this](const std::any& payload) {
            machine_file_status = "Invalid";
            auto code = EventField(payload, "code");
            auto error = EventField(payload, "error");
            offline_cache_status = !code.empty() ? ("Machine file " + code)
                                                 : (!error.empty() ? error
                                                                   : "Machine file verify failed");
        });
        sdk->on(licenseseat::events::OFFLINE_TOKEN_FETCHING, [this](const std::any&) {
            if (!legacy_offline_tokens_enabled) return;
            offline_token_status = "Syncing";
            if (!machine_file_cached) {
                offline_cache_status = "Requesting legacy token...";
            }
        });
        sdk->on(licenseseat::events::OFFLINE_TOKEN_READY, [this](const std::any&) {
            if (!legacy_offline_tokens_enabled) return;
            offline_token_status = "Cached";
            offline_cache_status = "Legacy token cached";
            refresh_cache_status();
            queue_toast("Legacy token ready", ORANGE);
        });
        sdk->on(licenseseat::events::OFFLINE_TOKEN_FETCH_ERROR, [this](const std::any&) {
            if (!legacy_offline_tokens_enabled) return;
            offline_token_status = "Failed";
            offline_cache_status = "Legacy token fetch failed";
            refresh_cache_status();
        });
#endif
    }

    void restore_on_startup() {
#if WASM_DEMO_MODE
        // No restore in WASM demo mode
#else
        // Run restore async to avoid blocking startup
        sdk->restore_license_async([this](licenseseat::RestoreResult result) {
            refresh_cache_status();
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
#endif
    }
};

void DrawWaveform(Rectangle bounds, Color color, float dt) {
    float waveform[256];
    GenerateDisplayWaveform(waveform, 256, dt);

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

    // Check Enter key BEFORE GuiTextBox consumes it
    bool enterPressed = state.key_input_edit && IsKeyPressed(KEY_ENTER);

    Rectangle inputBox = {(float)(x + 24), (float)(y + 60), (float)(w - 48), 36};
    if (GuiTextBox(inputBox, state.key_input, 64, state.key_input_edit)) {
        // Only toggle edit mode if not submitting with Enter
        if (!enterPressed) {
            state.key_input_edit = !state.key_input_edit;
        }
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

#if WASM_DEMO_MODE
    // WASM Demo: Mock validation with Stripe-style test keys
    if (GuiButton({(float)(x + 24), (float)(y + h - 55), 90, 36}, "Activate") || enterPressed) {
        std::string key(state.key_input);
        if (!key.empty()) {
            auto result = MockValidate(key);
            if (result.valid) {
                state.licensed = true;
                state.license_key = key;
                state.license_status = "Activated!";
                state.toast.show("Pro unlocked!", GREEN);
                state.show_license_modal = false;
                state.key_input_edit = false;
            } else {
                state.license_status = result.error_message;
                state.toast.show(result.error_code.c_str(), MAROON);
            }
        }
    }

    // Deactivate button for WASM
    if (GuiButton({(float)(x + 124), (float)(y + h - 55), 100, 36}, "Deactivate")) {
        state.licensed = false;
        state.license_key.clear();
        state.license_status = "Deactivated";
        memset(state.key_input, 0, sizeof(state.key_input));
        {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.wave_type = WAVE_SINE;
        }
        state.toast.show("License cleared", ORANGE);
        state.show_license_modal = false;
        state.key_input_edit = false;
    }
#else
    // Activate button - use async to avoid UI freeze
    if (state.activating || state.deactivating) {
        GuiSetState(STATE_DISABLED);
        GuiButton({(float)(x + 24), (float)(y + h - 55), 90, 36}, "...");
        GuiSetState(STATE_NORMAL);
    } else if (GuiButton({(float)(x + 24), (float)(y + h - 55), 90, 36}, "Activate") || enterPressed) {
        std::string key(state.key_input);
        if (!key.empty() && state.sdk) {
            state.activating = true;
            state.license_status = "Activating...";
            state.machine_file_status = "Syncing";
            state.offline_token_status = state.legacy_offline_tokens_enabled ? "Missing" : "";
            state.offline_cache_status = state.legacy_offline_tokens_enabled
                ? "Syncing offline artifacts..."
                : "Syncing machine file...";

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

    if (state.deactivating) {
        GuiSetState(STATE_DISABLED);
        GuiButton({(float)(x + 124), (float)(y + h - 55), 100, 36}, "...");
        GuiSetState(STATE_NORMAL);
    } else if (GuiButton({(float)(x + 124), (float)(y + h - 55), 100, 36}, "Deactivate")) {
        if (!state.sdk) {
            return;
        }

        std::string key = state.license_key.empty() ? std::string(state.key_input) : state.license_key;
        if (key.empty()) {
            state.sdk->reset();
            state.licensed = false;
            state.license_key.clear();
            state.license_status = "Cleared local data";
            state.machine_file_status.clear();
            state.offline_token_status.clear();
            state.offline_cache_status.clear();
            state.refresh_cache_status();
            {
                std::lock_guard<std::mutex> lock(g_synth.mtx);
                g_synth.wave_type = WAVE_SINE;
            }
            memset(state.key_input, 0, sizeof(state.key_input));
            state.toast.show("Local data cleared", ORANGE);
        } else {
            state.deactivating = true;
            state.license_status = "Deactivating...";

            state.sdk->deactivate_async(
                key,
                [&state](licenseseat::Result<licenseseat::Deactivation> result) {
                    if (result.is_ok() ||
                        result.error_code() == licenseseat::ErrorCode::ActivationNotFound) {
                        state.sdk->reset();
                        state.licensed = false;
                        state.license_key.clear();
                        state.license_status =
                            result.is_ok() ? "Deactivated" : "Activation not found";
                        state.machine_file_status.clear();
                        state.offline_token_status.clear();
                        state.offline_cache_status.clear();
                        state.refresh_cache_status();
                        {
                            std::lock_guard<std::mutex> lock(g_synth.mtx);
                            g_synth.wave_type = WAVE_SINE;
                        }
                        memset(state.key_input, 0, sizeof(state.key_input));
                        state.queue_toast(result.is_ok() ? "Device deactivated" : "Local data cleared",
                                          result.is_ok() ? ORANGE : GRAY);
                        state.show_license_modal = false;
                        state.key_input_edit = false;
                    } else {
                        state.license_status = result.error_message();
                        state.queue_toast("Deactivation failed", MAROON);
                    }

                    state.deactivating = false;
                },
                state.sdk->fingerprint());
        }
    }
#endif

    if (GuiButton({(float)(x + w - 80), (float)(y + h - 55), 60, 36}, "Close")) {
        state.show_license_modal = false;
        state.key_input_edit = false;
    }
}

#if !WASM_DEMO_MODE
void DrawAdminModal(AppState& state) {
    if (!state.show_admin_modal) return;

    DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), ColorAlpha(BLACK, 0.85f));

    int margin = 16;
    int w = GetScreenWidth() - margin * 2;
    int h = GetScreenHeight() - margin * 2;
    int x = margin;
    int y = margin;

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
    DrawText(ShortenMiddle(ApiEndpointHost(state.sdk_config.api_url), 16).c_str(), col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("Path:", col1X, row, 12, LIGHTGRAY);
    DrawText(ShortenMiddle(ApiEndpointPath(state.sdk_config.api_url), 14).c_str(), col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("Product:", col1X, row, 12, LIGHTGRAY);
    DrawText(state.sdk_config.product_slug.c_str(), col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("API Key:", col1X, row, 12, LIGHTGRAY);
    DrawText(ShortenMiddle(state.sdk_config.api_key, 12).c_str(), col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("Storage:", col1X, row, 12, LIGHTGRAY);
    DrawText(ShortenMiddle(state.sdk_config.storage_path, 14).c_str(), col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("Timeout:", col1X, row, 12, LIGHTGRAY);
    DrawText(TextFormat("%ds", state.sdk_config.timeout_seconds), col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("Fingerpr:", col1X, row, 12, LIGHTGRAY);
    DrawText(ShortenMiddle(state.sdk->fingerprint(), 16).c_str(), col1ValX, row, 12, WHITE);
    row += 15;

    DrawText("SSL:", col1X, row, 12, LIGHTGRAY);
    DrawText(state.sdk_config.verify_ssl ? "Yes" : "No", col1ValX, row, 12,
             state.sdk_config.verify_ssl ? GREEN : ORANGE);
    int configBottom = row + 15;

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
    row += 15;

    DrawText("Machine:", col2X, row, 12, LIGHTGRAY);
    DrawText(state.machine_file_status.c_str(), col2ValX, row, 12,
             CacheBadgeColor(state.machine_file_status, SKYBLUE));
    row += 15;

    if (state.legacy_offline_tokens_enabled || state.offline_token_cached ||
        !state.offline_token_status.empty()) {
        DrawText("Token:", col2X, row, 12, LIGHTGRAY);
        DrawText(state.offline_token_status.c_str(), col2ValX, row, 12,
                 CacheBadgeColor(state.offline_token_status, ORANGE));
        row += 15;
    }

    DrawText("Cache:", col2X, row, 12, LIGHTGRAY);
    DrawText(state.offline_cache_status.empty() ? "(idle)"
                                                : ShortenMiddle(state.offline_cache_status, 22).c_str(),
             col2ValX, row, 12,
             state.machine_file_cached ? SKYBLUE : (state.offline_token_cached ? ORANGE : GRAY));
    int runtimeBottom = row + 15;

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
        row += 15;
    } else {
        DrawText("(no license)", col3X, row + 30, 12, GRAY);
        row += 45;
    }
    int licenseBottom = row;

    // Separator
    int sepY = std::min(std::max(configBottom, std::max(runtimeBottom, licenseBottom)) + 8, y + h - 130);
    DrawLine(x + 24, sepY, x + w - 24, sepY, GetColor(0x404040ff));

    // Bottom section - three columns
    int detailY = sepY + 10;
    int col1 = x + 24;
    int col2 = x + 260;
    int col3 = x + 480;

    // Column 1: License Key
    DrawText("KEY", col1, detailY, 10, GOLD);
    int keyY = detailY + 12;
    if (!state.license_key.empty()) {
        DrawText(state.license_key.c_str(), col1, keyY, 10, WHITE);
    } else {
        DrawText("(none)", col1, keyY, 10, GRAY);
    }

    // Column 2: Metadata
    DrawText("METADATA", col2, detailY, 10, GOLD);
    int metaY = detailY + 12;
    if (valResult.valid && !valResult.license.metadata().empty()) {
        int count = 0;
        for (const auto& [k, v] : valResult.license.metadata()) {
            if (count >= 3) { DrawText("...", col2, metaY, 10, GRAY); break; }
            std::string kv = k + "=" + (v.length() > 15 ? v.substr(0,15) + ".." : v);
            DrawText(kv.c_str(), col2, metaY, 10, WHITE);
            metaY += 11;
            count++;
        }
    } else {
        DrawText("(none)", col2, metaY, 10, GRAY);
    }

    // Column 3: Entitlements
    DrawText("ENTITLEMENTS", col3, detailY, 10, GOLD);
    int entY = detailY + 12;
    if (valResult.valid && !valResult.license.active_entitlements().empty()) {
        int count = 0;
        for (const auto& ent : valResult.license.active_entitlements()) {
            if (count >= 3) { DrawText("...", col3, entY, 10, GRAY); break; }
            std::string entLine = ent.key;
            if (!ent.expires_at.has_value()) {
                entLine += " (perpetual)";
            }
            DrawText(entLine.c_str(), col3, entY, 10, WHITE);
            entY += 11;
            count++;
        }
    } else {
        DrawText("(none)", col3, entY, 10, GRAY);
    }

    // Bottom buttons
    int btnY = y + h - 50;

    if (GuiButton({(float)(x + 24), (float)btnY, 130, 32}, "Clear All Data")) {
        if (state.sdk) state.sdk->reset();
        state.licensed = false;
        state.license_key.clear();
        state.license_status.clear();
        state.machine_file_status.clear();
        state.offline_token_status.clear();
        state.offline_cache_status.clear();
        state.refresh_cache_status();
        {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.wave_type = WAVE_SINE;
        }
        memset(state.key_input, 0, sizeof(state.key_input));
        state.toast.show("All data cleared", ORANGE);
    }

    if (GuiButton({(float)(x + 168), (float)btnY, 110, 32}, "Sync Offline")) {
        if (state.sdk && !state.license_key.empty()) {
            state.machine_file_status = "Syncing";
            state.offline_token_status = state.legacy_offline_tokens_enabled
                ? (state.offline_token_cached ? "Cached" : "Missing")
                : "";
            state.offline_cache_status = state.legacy_offline_tokens_enabled
                ? "Refreshing offline artifacts..."
                : "Refreshing machine file...";
            state.sdk->sync_offline_assets();
            state.toast.show(state.legacy_offline_tokens_enabled ? "Syncing offline artifacts"
                                                                 : "Syncing machine file",
                             SKYBLUE);
        }
    }

    if (GuiButton({(float)(x + 290), (float)btnY, 100, 32}, "Machine File")) {
        state.show_machine_file_modal = true;
    }

    if (GuiButton({(float)(x + w - 70), (float)btnY, 55, 32}, "Close")) {
        state.show_admin_modal = false;
    }
}
#endif  // !WASM_DEMO_MODE

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

void DrawHelpModal(AppState& state) {
    if (!state.show_help_modal) return;

    DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), ColorAlpha(BLACK, 0.85f));

    int w = 480, h = 340;
    int x = (GetScreenWidth() - w) / 2;
    int y = (GetScreenHeight() - h) / 2;

    DrawRectangle(x, y, w, h, GetColor(0x252525ff));
    DrawRectangleLinesEx({(float)x, (float)y, (float)w, (float)h}, 2, GetColor(0x555555ff));

    DrawText("Keyboard Shortcuts", x + 24, y + 20, 20, WHITE);

    int row = y + 55;
    int col1 = x + 24;
    int col2 = x + 140;
    int lineH = 22;

    DrawText("Space", col1, row, 14, SKYBLUE); DrawText("Play / Stop", col2, row, 14, LIGHTGRAY); row += lineH;
    DrawText("P", col1, row, 14, SKYBLUE); DrawText("Toggle snap to note", col2, row, 14, LIGHTGRAY); row += lineH;
    DrawText("Left/Right", col1, row, 14, SKYBLUE); DrawText("Adjust frequency (1Hz or 1 semitone)", col2, row, 14, LIGHTGRAY); row += lineH;
    DrawText("Page Up/Dn", col1, row, 14, SKYBLUE); DrawText("Change octave (0-9)", col2, row, 14, LIGHTGRAY); row += lineH;

    row += 10;
    DrawText("Piano Keys", x + 24, row, 16, GOLD); row += 24;

    DrawText("S D   G H J   L ;", col1, row, 14, WHITE);
    DrawText("Black keys (C# D# F# G# A#...)", col2 + 40, row, 14, LIGHTGRAY); row += lineH;

    DrawText("Z X C V B N M , . /", col1, row, 14, WHITE);
    DrawText("White keys (C D E F G A B...)", col2 + 40, row, 14, LIGHTGRAY); row += lineH;

    row += 10;
    DrawText("Snap Mode", x + 24, row, 16, GOLD); row += 24;
    DrawText("When enabled, frequency snaps to exact musical notes.", col1, row, 13, LIGHTGRAY); row += 18;
    DrawText("Arrow keys move by semitone. Piano keys play in tune.", col1, row, 13, LIGHTGRAY);

    if (GuiButton({(float)(x + w - 80), (float)(y + h - 52), 60, 36}, "Close")) {
        state.show_help_modal = false;
    }
}

#if !WASM_DEMO_MODE
void DrawMachineFileModal(AppState& state) {
    if (!state.show_machine_file_modal) return;

    DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), ColorAlpha(BLACK, 0.85f));

    int w = 620, h = 320;
    int x = (GetScreenWidth() - w) / 2;
    int y = (GetScreenHeight() - h) / 2;

    DrawRectangle(x, y, w, h, GetColor(0x252525ff));
    DrawRectangleLinesEx({(float)x, (float)y, (float)w, (float)h}, 2, GetColor(0x555555ff));

    DrawText("Machine File", x + 20, y + 16, 18, WHITE);

    auto storage_path = state.sdk_config.storage_path.empty()
        ? std::string(DEMO_STORAGE_PATH) : state.sdk_config.storage_path;
    auto info = LoadMachineFileInfo(storage_path, state.sdk.get());

    int row = y + 45;
    int col1X = x + 20;
    int col1ValX = x + 100;
    int col2X = x + 320;
    int col2ValX = x + 410;
    int lineH = 15;

    if (!info.loaded) {
        DrawText("No machine file cached.", col1X, row, 12, GRAY);
        DrawText("Activate a license and sync offline to generate one.", col1X, row + 18, 11, DARKGRAY);
    } else {
        // ENVELOPE section
        DrawText("ENVELOPE", col1X, row, 10, GOLD); row += 14;

        DrawText("Algorithm:", col1X, row, 11, LIGHTGRAY);
        DrawText(info.algorithm.c_str(), col1ValX, row, 11, WHITE);
        DrawText("TTL:", col2X, row, 11, LIGHTGRAY);
        DrawText(TextFormat("%lld sec (%d days)", info.ttl, (int)(info.ttl / 86400)), col2ValX, row, 11, WHITE);
        row += lineH;

        DrawText("Issued:", col1X, row, 11, LIGHTGRAY);
        DrawText(info.issued.empty() ? "-" : info.issued.c_str(), col1ValX, row, 11, WHITE);
        DrawText("Expiry:", col2X, row, 11, LIGHTGRAY);
        DrawText(info.expiry.empty() ? "-" : info.expiry.c_str(), col2ValX, row, 11, WHITE);
        row += lineH;

        DrawText("License:", col1X, row, 11, LIGHTGRAY);
        DrawText(info.license_key.c_str(), col1ValX, row, 11, SKYBLUE);
        DrawText("Fingerprint:", col2X, row, 11, LIGHTGRAY);
        DrawText(ShortenMiddle(info.fingerprint, 20).c_str(), col2ValX, row, 11, WHITE);
        row += lineH + 8;

        // Separator
        DrawLine(col1X, row, x + w - 20, row, GetColor(0x444444ff));
        row += 10;

        // DECRYPTED PAYLOAD section
        if (info.verified) {
            DrawText("DECRYPTED PAYLOAD", col1X, row, 10, GOLD); row += 14;

            DrawText("iat:", col1X, row, 11, LIGHTGRAY);
            DrawText(TextFormat("%lld (%s)", info.iat, FormatUnixTime(info.iat).c_str()), col1ValX, row, 11, WHITE);
            row += lineH;

            DrawText("exp:", col1X, row, 11, LIGHTGRAY);
            DrawText(TextFormat("%lld (%s)", info.exp, FormatUnixTime(info.exp).c_str()), col1ValX, row, 11, WHITE);
            row += lineH;

            DrawText("nbf:", col1X, row, 11, LIGHTGRAY);
            DrawText(TextFormat("%lld (%s)", info.nbf, FormatUnixTime(info.nbf).c_str()), col1ValX, row, 11, WHITE);
            DrawText("grace:", col2X, row, 11, LIGHTGRAY);
            DrawText(TextFormat("%lld sec", info.grace_period), col2ValX, row, 11, WHITE);
            row += lineH;

            DrawText("Machine:", col1X, row, 11, LIGHTGRAY);
            DrawText(ShortenMiddle(info.machine_id, 24).c_str(), col1ValX, row, 11, WHITE);
            DrawText("Platform:", col2X, row, 11, LIGHTGRAY);
            DrawText(info.platform.empty() ? "-" : info.platform.c_str(), col2ValX, row, 11, WHITE);
            row += lineH;

            DrawText("Device:", col1X, row, 11, LIGHTGRAY);
            DrawText(info.device_name.empty() ? "-" : ShortenMiddle(info.device_name, 24).c_str(), col1ValX, row, 11, WHITE);
            DrawText("Key ID:", col2X, row, 11, LIGHTGRAY);
            DrawText(ShortenMiddle(info.key_id, 20).c_str(), col2ValX, row, 11, WHITE);
            row += lineH + 4;

            // Metadata and Entitlements side by side
            int metaX = col1X;
            int entX = col2X;

            DrawText("METADATA", metaX, row, 10, GOLD);
            DrawText("ENTITLEMENTS", entX, row, 10, GOLD);
            row += 14;

            int metaRow = row;
            int entRow = row;

            if (info.metadata.empty()) {
                DrawText("(none)", metaX, metaRow, 10, GRAY);
            } else {
                int count = 0;
                for (const auto& [k, v] : info.metadata) {
                    if (count >= 4) { DrawText("...", metaX, metaRow, 10, GRAY); break; }
                    std::string kv = k + "=" + (v.length() > 12 ? v.substr(0, 12) + ".." : v);
                    DrawText(kv.c_str(), metaX, metaRow, 10, WHITE);
                    metaRow += 12;
                    count++;
                }
            }

            if (info.entitlements.empty()) {
                DrawText("(none)", entX, entRow, 10, GRAY);
            } else {
                int count = 0;
                for (const auto& ent : info.entitlements) {
                    if (count >= 4) { DrawText("...", entX, entRow, 10, GRAY); break; }
                    std::string line = ent.key + (ent.expires_at ? "" : " (perpetual)");
                    DrawText(line.c_str(), entX, entRow, 10, WHITE);
                    entRow += 12;
                    count++;
                }
            }
        } else {
            DrawText("DECRYPTED PAYLOAD", col1X, row, 10, DARKGRAY);
            DrawText("Verification failed or key mismatch", col1X + 130, row, 10, GRAY);
        }
    }

    if (GuiButton({(float)(x + w - 70), (float)(y + h - 42), 55, 30}, "Close")) {
        state.show_machine_file_modal = false;
    }
}
#endif  // !WASM_DEMO_MODE

int main() {
    const int screenWidth = 720;
    const int screenHeight = 360;

#ifdef __EMSCRIPTEN__
    SetConfigFlags(FLAG_VSYNC_HINT | FLAG_WINDOW_HIGHDPI);
#else
    SetConfigFlags(FLAG_VSYNC_HINT);
#endif
    InitWindow(screenWidth, screenHeight, TextFormat("%s v%s", TOOL_NAME, TOOL_VERSION));
    SetExitKey(0);  // Disable ESC closing the app
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
#if !WASM_DEMO_MODE
    state.init_sdk();
    state.restore_on_startup();
#endif

    while (!WindowShouldClose()) {
        float dt = GetFrameTime();
        state.toast.update(dt);
#if !WASM_DEMO_MODE
        state.process_pending_toast();
#endif

        int w = GetScreenWidth();
        int h = GetScreenHeight();

#if !WASM_DEMO_MODE
        auto client_status = state.sdk->get_client_status();
        bool is_currently_licensed =
            client_status == licenseseat::ClientStatus::Active ||
            client_status == licenseseat::ClientStatus::OfflineValid;
        if (state.licensed != is_currently_licensed) {
#else
        bool is_currently_licensed = state.licensed;
        if (false) {  // No auto-sync in WASM
#endif
            state.licensed = is_currently_licensed;
            if (!state.licensed) {
                std::lock_guard<std::mutex> lock(g_synth.mtx);
                g_synth.wave_type = WAVE_SINE;
            }
        }

#if WASM_DEMO_MODE
        bool modalOpen = state.show_license_modal || state.show_about_modal || state.show_help_modal;
#else
        bool modalOpen = state.show_license_modal || state.show_about_modal || state.show_admin_modal || state.show_help_modal || state.show_machine_file_modal;
#endif
        if (modalOpen) GuiLock(); else GuiUnlock();

        // Keyboard shortcuts (only when no modal open)
        if (!modalOpen) {
            // Arrow keys for frequency
            bool left = IsKeyPressed(KEY_LEFT) || IsKeyPressedRepeat(KEY_LEFT);
            bool right = IsKeyPressed(KEY_RIGHT) || IsKeyPressedRepeat(KEY_RIGHT);
            if (left || right) {
                std::lock_guard<std::mutex> lock(g_synth.mtx);
                if (g_synth.snap_to_note) {
                    // Move by semitone
                    float semitone = 12.0f * log2f(g_synth.frequency / 440.0f) + 69.0f;
                    semitone += right ? 1.0f : -1.0f;
                    g_synth.frequency = 440.0f * powf(2.0f, (semitone - 69.0f) / 12.0f);
                } else {
                    // Move by 1 Hz
                    g_synth.frequency += right ? 1.0f : -1.0f;
                }
                g_synth.frequency = fmaxf(16.0f, fminf(9000.0f, g_synth.frequency));
            }

            // Space for play/stop
            if (IsKeyPressed(KEY_SPACE)) {
                std::lock_guard<std::mutex> lock(g_synth.mtx);
                g_synth.playing = !g_synth.playing;
            }

            // P for snap toggle
            if (IsKeyPressed(KEY_P)) {
                g_synth.snap_to_note = !g_synth.snap_to_note;
            }

            // Page Up/Down for octave change
            if (IsKeyPressed(KEY_PAGE_UP)) {
                if (g_synth.octave < 9) g_synth.octave++;
            }
            if (IsKeyPressed(KEY_PAGE_DOWN)) {
                if (g_synth.octave > 0) g_synth.octave--;
            }

            // Piano keyboard mapping (uses explicit octave)
            // White keys (bottom row): Z X C V B N M , . /
            // Black keys (row above):  S D   G H J   L ;
            struct KeyNote { int key; int semitone; };  // semitone offset from C
            static const KeyNote pianoKeys[] = {
                // White keys (bottom row)
                {KEY_Z, 0},   // C
                {KEY_X, 2},   // D
                {KEY_C, 4},   // E
                {KEY_V, 5},   // F
                {KEY_B, 7},   // G
                {KEY_N, 9},   // A
                {KEY_M, 11},  // B
                {KEY_COMMA, 12},  // C+1
                {KEY_PERIOD, 14}, // D+1
                {KEY_SLASH, 16},  // E+1
                // Black keys (row above)
                {KEY_S, 1},   // C#
                {KEY_D, 3},   // D#
                {KEY_G, 6},   // F#
                {KEY_H, 8},   // G#
                {KEY_J, 10},  // A#
                {KEY_L, 13},  // C#+1
                {KEY_SEMICOLON, 15}, // D#+1
            };
            for (const auto& pk : pianoKeys) {
                if (IsKeyPressed(pk.key)) {
                    std::lock_guard<std::mutex> lock(g_synth.mtx);
                    // Use explicit octave (C4 = MIDI 60)
                    int baseMidi = (g_synth.octave + 1) * 12;  // C of current octave
                    float newFreq = 440.0f * powf(2.0f, (baseMidi + pk.semitone - 69.0f) / 12.0f);
                    // Clamp to valid range
                    g_synth.frequency = fmaxf(16.0f, fminf(9000.0f, newFreq));
                    g_synth.phase = 0.0f;  // Reset phase for retrigger effect
                    g_synth.envelope = 0.0f;  // Reset envelope for attack
                    g_synth.playing = true;
                }
            }
        }

        BeginDrawing();
        ClearBackground(GetColor(0x1a1a1aff));

        // === Header ===
        DrawRectangle(0, 0, w, 52, GetColor(0x222222ff));
        DrawLine(0, 52, w, 52, GetColor(0x3a3a3aff));

        DrawText(TOOL_NAME, 16, 14, 24, WHITE);
        DrawText(TextFormat("v%s", TOOL_VERSION), 150, 18, 16, GRAY);

#if !WASM_DEMO_MODE
        // SDK status dot (left of license badge)
        {
            Color sc = GRAY;
            if (client_status == licenseseat::ClientStatus::Active) sc = GREEN;
            else if (client_status == licenseseat::ClientStatus::OfflineValid) sc = ORANGE;
            else if (client_status == licenseseat::ClientStatus::Invalid) sc = MAROON;
            DrawCircle(w - 112, 26, 8, sc);
        }
#endif

        // License badge (right-aligned with 16px margin, same as other controls)
        {
            int bx = w - 96;
            Color bc = state.licensed ? GREEN : GRAY;
            const char* bt = state.licensed ? "PRO" : "FREE";
            DrawRectangle(bx, 10, 80, 32, ColorAlpha(bc, 0.2f));
            DrawRectangleLinesEx({(float)bx, 10, 80, 32}, 2, bc);
            DrawText(bt, bx + (state.licensed ? 22 : 16), 17, 18, bc);
        }

        // === Waveform ===
        int contentY = 62;
        Rectangle waveRect = {16, (float)contentY, (float)(w - 32), 120};
        Color waveCol = state.licensed ? SKYBLUE : GetColor(0x5a9a5aff);
        if (g_synth.playing) waveCol = state.licensed ? GREEN : GetColor(0x7aba7aff);
        DrawWaveform(waveRect, waveCol, dt);

        // Wave name & frequency
        const char* waveNames[] = {"Square", "Sawtooth", "Sine", "Noise"};
        DrawText(waveNames[g_synth.wave_type], 28, contentY + 12, 20, ColorAlpha(WHITE, 0.9f));

        // Freq (upper right of waveform)
        const char* freqStr = TextFormat("%.0f Hz", g_synth.frequency);
        int freqWidth = MeasureText(freqStr, 18);
        DrawText(freqStr, w - 28 - freqWidth, contentY + 12, 18, GRAY);

        // Note display (lower right of waveform)
        std::string noteStr = FreqToNote(g_synth.frequency);
        int noteWidth = MeasureText(noteStr.c_str(), 18);
        DrawText(noteStr.c_str(), w - 28 - noteWidth, contentY + 120 - 24, 18, SKYBLUE);

        // === Controls ===
        int ctrlY = contentY + 132;
        int btnH = 36;

        // === Row 1: Freq slider + Snap ===
        DrawText("Freq", 16, ctrlY + 8, 18, LIGHTGRAY);
        const float freqMin = 16.0f, freqMax = 9000.0f;
        float logPos = log2f(g_synth.frequency / freqMin) / log2f(freqMax / freqMin);
        int freqSliderWidth = w - 70 - 70 - 16;
        GuiSlider({70, (float)ctrlY, (float)freqSliderWidth, 32}, NULL, NULL, &logPos, 0.0f, 1.0f);
        float newFreq = freqMin * powf(freqMax / freqMin, logPos);

        int snapX = w - 70;
        if (GuiButton({(float)snapX, (float)ctrlY, 54, 32}, "Snap")) {
            g_synth.snap_to_note = !g_synth.snap_to_note;
        }
        if (g_synth.snap_to_note) {
            DrawRectangleLinesEx({(float)snapX, (float)ctrlY, 54, 32}, 2, SKYBLUE);
        }

        {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.frequency = g_synth.snap_to_note ? SnapToNote(newFreq) : newFreq;
        }

        // === Row 2: Wave selector + Play/Stop ===
        int waveY = ctrlY + 48;
        int x = 16;

        DrawText("Wave", x, waveY + 10, 18, LIGHTGRAY);
        x += 60;

        // Sine (FREE)
        bool sineActive = g_synth.wave_type == WAVE_SINE;
        if (GuiButton({(float)x, (float)waveY, 90, (float)btnH}, "Sine")) {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.wave_type = WAVE_SINE;
        }
        if (sineActive) {
            DrawRectangleLinesEx({(float)x, (float)waveY, 90, (float)btnH}, 3, WHITE);
        }
        x += 100;

        // PRO buttons
        auto drawProBtn = [&](const char* label, WaveType type) {
            bool active = g_synth.wave_type == type;
            if (state.licensed) {
                if (GuiButton({(float)x, (float)waveY, 90, (float)btnH}, label)) {
                    std::lock_guard<std::mutex> lock(g_synth.mtx);
                    g_synth.wave_type = type;
                }
                if (active) {
                    DrawRectangleLinesEx({(float)x, (float)waveY, 90, (float)btnH}, 3, WHITE);
                }
            } else {
                GuiSetState(STATE_DISABLED);
                GuiButton({(float)x, (float)waveY, 90, (float)btnH}, label);
                GuiSetState(STATE_NORMAL);
                DrawText("PRO", x + 90 - 25, waveY + 24, 10, GOLD);
                if (CheckCollisionPointRec(GetMousePosition(), {(float)x, (float)waveY, 90, (float)btnH}) &&
                    IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
                    state.show_license_modal = true;
                }
            }
            x += 100;
        };

        drawProBtn("Sawtooth", WAVE_SAWTOOTH);
        drawProBtn("Square", WAVE_SQUARE);
        drawProBtn("Noise", WAVE_NOISE);

        // Play/Stop (right side of wave row)
        int playBtnW = 100;
        int playBtnX = w - playBtnW - 16;
        Color playBtnCol = g_synth.playing ? GetColor(0x3a6a3aff) : GetColor(0x2a2a2aff);
        DrawRectangle(playBtnX, waveY, playBtnW, btnH, playBtnCol);
        if (GuiButton({(float)playBtnX, (float)waveY, (float)playBtnW, (float)btnH}, "")) {
            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.playing = !g_synth.playing;
        }
        int iconX = playBtnX + 16;
        int iconCenterY = waveY + btnH / 2;
        if (g_synth.playing) {
            int sqSize = 12;
            DrawRectangle(iconX, iconCenterY - sqSize/2, sqSize, sqSize, WHITE);
            DrawText("Stop", iconX + sqSize + 10, waveY + 10, 16, WHITE);
        } else {
            Vector2 center = {(float)(iconX + 6), (float)iconCenterY};
            DrawPoly(center, 3, 9, 120, WHITE);
            DrawText("Play", iconX + 22, waveY + 10, 16, WHITE);
        }

        // === Bottom bar ===
        int bottomY = h - 48;
        DrawRectangle(0, bottomY, w, 48, GetColor(0x1e1e1eff));
        DrawLine(0, bottomY, w, bottomY, GetColor(0x3a3a3aff));

        if (GuiButton({16, (float)(bottomY + 6), 50, 36}, "Help")) {
            state.show_help_modal = true;
        }

        if (GuiButton({76, (float)(bottomY + 6), 60, 36}, "About")) {
            state.show_about_modal = true;
        }

        if (GuiButton({146, (float)(bottomY + 6), 90, 36}, state.licensed ? "License" : "Activate")) {
            if (!state.license_key.empty()) strncpy(state.key_input, state.license_key.c_str(), 63);
            state.show_license_modal = true;
        }

#if !WASM_DEMO_MODE
        if (GuiButton({246, (float)(bottomY + 6), 90, 36}, "SDK Admin")) {
            state.show_admin_modal = true;
        }
#endif

        // Volume slider (bottom right, right-aligned with 16px margin)
        {
            int sliderW = 110;
            int sliderX = w - 16 - sliderW;
            Rectangle sliderRect = {(float)sliderX, (float)(bottomY + 8), (float)sliderW, 28};

            DrawText("Vol", sliderX - 36, bottomY + 14, 14, LIGHTGRAY);

            float vv = g_synth.volume;
            GuiSlider(sliderRect, NULL, NULL, &vv, 0.0f, 1.0f);

            // Draw percentage inside slider (right side)
            const char* pctText = TextFormat("%.0f%%", vv * 100);
            int pctWidth = MeasureText(pctText, 12);
            DrawText(pctText, sliderX + sliderW - pctWidth - 8, bottomY + 16, 12, ColorAlpha(WHITE, 0.7f));

            std::lock_guard<std::mutex> lock(g_synth.mtx);
            g_synth.volume = vv;
        }

        // === Modals ===
        GuiUnlock();
        DrawLicenseModal(state);
        DrawAboutModal(state);
#if !WASM_DEMO_MODE
        DrawAdminModal(state);
        DrawMachineFileModal(state);
#endif
        DrawHelpModal(state);
        state.toast.draw(w, h);

        EndDrawing();
    }

    StopAudioStream(stream);
    UnloadAudioStream(stream);
    CloseAudioDevice();
    CloseWindow();
    return 0;
}
