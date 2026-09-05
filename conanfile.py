from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.files import copy
import os


class LicenseSeatConan(ConanFile):
    name = "licenseseat"
    version = "0.7.0"
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

    exports_sources = (
        "CMakeLists.txt",
        "src/*",
        "include/*",
        "deps/*",
        "cmake/*",
        "tests/*",
        "LICENSE",
        "THIRD_PARTY_LICENSES.md",
    )

    def requirements(self):
        self.requires("openssl/3.5.7")

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
        licenses = os.path.join(self.package_folder, "licenses")
        copy(self, "LICENSE", src=self.source_folder, dst=licenses)
        copy(self, "THIRD_PARTY_LICENSES.md", src=self.source_folder, dst=licenses)

    def package_info(self):
        self.cpp_info.libs = ["licenseseat"]
        self.cpp_info.set_property("cmake_file_name", "licenseseat")
        self.cpp_info.set_property("cmake_target_name", "licenseseat::licenseseat")
        # OpenSSL is a public dependency for HTTPS, Ed25519 verification, and
        # machine-file AES-GCM support. JSON and HTTP use the audited copies
        # exported with this recipe rather than unrelated Conan packages.
        self.cpp_info.requires = ["openssl::openssl"]
