/**
 * ImageTool Pro - Demo Application
 *
 * A simple demo app to showcase LicenseSeat SDK integration.
 * Currently standalone — licensing integration coming next.
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <functional>

// Feature flags (will be controlled by entitlements later)
struct Features {
    bool pro_filters = false;
    bool batch_export = false;
    bool cloud_sync = false;
    bool raw_support = false;
};

class ImageTool {
public:
    ImageTool() : licensed_(false) {}

    void run() {
        print_header();
        main_loop();
    }

private:
    bool licensed_;
    Features features_;
    std::string current_image_;

    void print_header() {
        std::cout << R"(
╔═══════════════════════════════════════════════════════════╗
║                    ImageTool Pro v1.0                     ║
║              Professional Image Processing                ║
╚═══════════════════════════════════════════════════════════╝
)" << std::endl;

        print_license_status();
    }

    void print_license_status() {
        std::cout << "License Status: ";
        if (licensed_) {
            std::cout << "✓ Licensed (Pro)\n";
            std::cout << "Features: ";
            if (features_.pro_filters) std::cout << "[Filters] ";
            if (features_.batch_export) std::cout << "[Batch] ";
            if (features_.cloud_sync) std::cout << "[Cloud] ";
            if (features_.raw_support) std::cout << "[RAW] ";
            std::cout << "\n";
        } else {
            std::cout << "✗ Free Edition (limited features)\n";
        }
        std::cout << std::string(60, '-') << "\n\n";
    }

    void main_loop() {
        bool running = true;
        while (running) {
            print_menu();
            int choice = get_choice();

            switch (choice) {
                case 1: open_image(); break;
                case 2: basic_edit(); break;
                case 3: apply_filter(); break;
                case 4: export_image(); break;
                case 5: batch_process(); break;
                case 6: cloud_sync(); break;
                case 7: activate_license(); break;
                case 8: show_license_info(); break;
                case 0: running = false; break;
                default: std::cout << "Invalid option.\n"; break;
            }
            std::cout << "\n";
        }
        std::cout << "Thanks for using ImageTool Pro!\n";
    }

    void print_menu() {
        std::cout << "=== Main Menu ===\n";
        std::cout << "  [1] Open Image\n";
        std::cout << "  [2] Basic Edit (crop, rotate)\n";
        std::cout << "  [3] Apply Filter" << (features_.pro_filters ? "" : " [PRO]") << "\n";
        std::cout << "  [4] Export Image\n";
        std::cout << "  [5] Batch Process" << (features_.batch_export ? "" : " [PRO]") << "\n";
        std::cout << "  [6] Cloud Sync" << (features_.cloud_sync ? "" : " [PRO]") << "\n";
        std::cout << "  ---\n";
        std::cout << "  [7] Activate License\n";
        std::cout << "  [8] License Info\n";
        std::cout << "  [0] Exit\n";
        std::cout << "\nChoice: ";
    }

    int get_choice() {
        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            return -1;
        }
        std::cin.ignore(10000, '\n');
        return choice;
    }

    // === Free Features ===

    void open_image() {
        std::cout << "\n[Open Image]\n";
        std::cout << "Enter image path: ";
        std::getline(std::cin, current_image_);

        if (current_image_.empty()) {
            current_image_ = "sample.jpg";
        }

        // Check RAW support
        if (is_raw_file(current_image_) && !features_.raw_support) {
            std::cout << "⚠ RAW file support requires Pro license.\n";
            std::cout << "  Supported free formats: JPG, PNG, BMP\n";
            current_image_.clear();
            return;
        }

        std::cout << "✓ Opened: " << current_image_ << "\n";
        std::cout << "  Size: 1920x1080 (simulated)\n";
        std::cout << "  Format: " << get_extension(current_image_) << "\n";
    }

    void basic_edit() {
        if (current_image_.empty()) {
            std::cout << "⚠ No image open. Use [1] to open an image first.\n";
            return;
        }

        std::cout << "\n[Basic Edit] - " << current_image_ << "\n";
        std::cout << "  [1] Rotate 90°\n";
        std::cout << "  [2] Crop\n";
        std::cout << "  [3] Resize\n";
        std::cout << "  [0] Back\n";
        std::cout << "Choice: ";

        int sub = get_choice();
        switch (sub) {
            case 1: std::cout << "✓ Image rotated 90° clockwise.\n"; break;
            case 2: std::cout << "✓ Image cropped to selection.\n"; break;
            case 3: std::cout << "✓ Image resized to 1280x720.\n"; break;
            case 0: break;
            default: std::cout << "Invalid option.\n"; break;
        }
    }

    void export_image() {
        if (current_image_.empty()) {
            std::cout << "⚠ No image open.\n";
            return;
        }

        std::cout << "\n[Export Image]\n";
        std::cout << "Export formats:\n";
        std::cout << "  [1] JPG (Free)\n";
        std::cout << "  [2] PNG (Free)\n";
        std::cout << "  [3] TIFF" << (licensed_ ? "" : " [PRO]") << "\n";
        std::cout << "  [4] WebP" << (licensed_ ? "" : " [PRO]") << "\n";
        std::cout << "Choice: ";

        int format = get_choice();
        if ((format == 3 || format == 4) && !licensed_) {
            show_upgrade_prompt("Export to TIFF/WebP");
            return;
        }

        std::string formats[] = {"", "jpg", "png", "tiff", "webp"};
        if (format >= 1 && format <= 4) {
            std::cout << "✓ Exported: output." << formats[format] << "\n";
        }
    }

    // === Pro Features ===

    void apply_filter() {
        if (current_image_.empty()) {
            std::cout << "⚠ No image open.\n";
            return;
        }

        std::cout << "\n[Filters] - " << current_image_ << "\n";
        std::cout << "  [1] Grayscale (Free)\n";
        std::cout << "  [2] Brightness (Free)\n";
        std::cout << "  [3] Pro: Cinematic LUT" << (features_.pro_filters ? "" : " [PRO]") << "\n";
        std::cout << "  [4] Pro: AI Enhance" << (features_.pro_filters ? "" : " [PRO]") << "\n";
        std::cout << "  [5] Pro: Noise Reduction" << (features_.pro_filters ? "" : " [PRO]") << "\n";
        std::cout << "Choice: ";

        int filter = get_choice();

        if (filter >= 3 && filter <= 5 && !features_.pro_filters) {
            show_upgrade_prompt("Pro Filters");
            return;
        }

        std::string filters[] = {"", "Grayscale", "Brightness +10", "Cinematic LUT", "AI Enhance", "Noise Reduction"};
        if (filter >= 1 && filter <= 5) {
            std::cout << "✓ Applied: " << filters[filter] << "\n";
        }
    }

    void batch_process() {
        if (!features_.batch_export) {
            show_upgrade_prompt("Batch Processing");
            return;
        }

        std::cout << "\n[Batch Process]\n";
        std::cout << "Processing 10 images...\n";
        for (int i = 1; i <= 10; ++i) {
            std::cout << "  [" << i << "/10] image_" << i << ".jpg ✓\n";
        }
        std::cout << "✓ Batch complete!\n";
    }

    void cloud_sync() {
        if (!features_.cloud_sync) {
            show_upgrade_prompt("Cloud Sync");
            return;
        }

        std::cout << "\n[Cloud Sync]\n";
        std::cout << "Syncing with ImageTool Cloud...\n";
        std::cout << "  ↑ Uploading 3 images...\n";
        std::cout << "  ↓ Downloading 2 presets...\n";
        std::cout << "✓ Sync complete!\n";
    }

    // === License Management ===

    void activate_license() {
        std::cout << "\n[Activate License]\n";
        std::cout << "Enter license key (or 'demo' for demo mode): ";
        std::string key;
        std::getline(std::cin, key);

        if (key.empty()) {
            std::cout << "⚠ No key entered.\n";
            return;
        }

        // TODO: Replace with actual LicenseSeat SDK call
        // auto result = client.validate(key);

        std::cout << "Validating...\n";

        if (key == "demo" || key == "DEMO-1234-5678-ABCD") {
            // Simulate successful activation
            licensed_ = true;
            features_.pro_filters = true;
            features_.batch_export = true;
            features_.cloud_sync = true;
            features_.raw_support = true;

            std::cout << "✓ License activated successfully!\n";
            std::cout << "  Plan: Pro\n";
            std::cout << "  Features unlocked: Filters, Batch, Cloud, RAW\n";
        } else {
            std::cout << "✗ Invalid license key.\n";
            std::cout << "  Try 'demo' to test Pro features.\n";
        }
    }

    void show_license_info() {
        std::cout << "\n[License Info]\n";
        std::cout << std::string(40, '-') << "\n";

        if (licensed_) {
            std::cout << "Status:     Licensed\n";
            std::cout << "Plan:       Pro\n";
            std::cout << "Expires:    2027-03-02\n";
            std::cout << "Device:     " << get_device_name() << "\n";
            std::cout << "\nEntitlements:\n";
            if (features_.pro_filters) std::cout << "  ✓ pro-filters\n";
            if (features_.batch_export) std::cout << "  ✓ batch-export\n";
            if (features_.cloud_sync) std::cout << "  ✓ cloud-sync\n";
            if (features_.raw_support) std::cout << "  ✓ raw-support\n";
        } else {
            std::cout << "Status:     Free Edition\n";
            std::cout << "Plan:       None\n";
            std::cout << "\nUpgrade to Pro for:\n";
            std::cout << "  • Professional filters & LUTs\n";
            std::cout << "  • Batch processing\n";
            std::cout << "  • Cloud sync & backup\n";
            std::cout << "  • RAW file support\n";
            std::cout << "\nVisit: https://imagetool.example/pricing\n";
        }
        std::cout << std::string(40, '-') << "\n";
    }

    void show_upgrade_prompt(const std::string& feature) {
        std::cout << "\n┌─────────────────────────────────────────┐\n";
        std::cout << "│  🔒 " << feature << " requires Pro license\n";
        std::cout << "│\n";
        std::cout << "│  Use [7] to activate your license\n";
        std::cout << "│  or visit: https://imagetool.example\n";
        std::cout << "└─────────────────────────────────────────┘\n";
    }

    // === Helpers ===

    bool is_raw_file(const std::string& path) {
        std::string ext = get_extension(path);
        return ext == "raw" || ext == "cr2" || ext == "nef" || ext == "arw" || ext == "dng";
    }

    std::string get_extension(const std::string& path) {
        size_t dot = path.rfind('.');
        if (dot == std::string::npos) return "";
        std::string ext = path.substr(dot + 1);
        for (char& c : ext) c = std::tolower(c);
        return ext;
    }

    std::string get_device_name() {
        #ifdef __APPLE__
        return "MacBook Pro";
        #elif _WIN32
        return "Windows PC";
        #else
        return "Linux Workstation";
        #endif
    }
};

int main() {
    ImageTool app;
    app.run();
    return 0;
}
