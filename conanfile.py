from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.files import copy
import os


class LicenseSeatConan(ConanFile):
    name = "licenseseat"
    version = "0.1.0"
    license = "MIT"
    author = "LicenseSeat"
    url = "https://github.com/licenseseat/licenseseat-cpp"
    description = "C++ SDK for LicenseSeat licensing API"
    topics = ("licensing", "sdk", "api", "http")

    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "build_tests": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "build_tests": False,
    }

    exports_sources = "CMakeLists.txt", "src/*", "include/*", "cmake/*", "tests/*", "LICENSE"

    def requirements(self):
        self.requires("openssl/3.2.0")
        self.requires("nlohmann_json/3.11.3")
        self.requires("cpp-httplib/0.15.3")

    def build_requirements(self):
        if self.options.build_tests:
            self.test_requires("gtest/1.14.0")

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.variables["LICENSESEAT_BUILD_TESTS"] = self.options.build_tests
        tc.variables["LICENSESEAT_BUILD_EXAMPLES"] = False
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
        copy(self, "LICENSE", src=self.source_folder, dst=os.path.join(self.package_folder, "licenses"))

    def package_info(self):
        self.cpp_info.libs = ["licenseseat"]
        self.cpp_info.set_property("cmake_file_name", "licenseseat")
        self.cpp_info.set_property("cmake_target_name", "licenseseat::licenseseat")
        # Note: OpenSSL is used by cpp-httplib for HTTPS, not by licenseseat directly
        self.cpp_info.requires = ["nlohmann_json::nlohmann_json", "cpp-httplib::cpp-httplib"]
