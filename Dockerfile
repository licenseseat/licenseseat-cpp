# LicenseSeat C++ SDK - Alpine Linux Build
#
# All dependencies are bundled except OpenSSL.
# Uses musl libc (fully compatible with the SDK).
#
# Build: docker build -t licenseseat-cpp .
# Test:  docker run licenseseat-cpp

FROM alpine:3.19

# Only need build tools and OpenSSL
RUN apk add --no-cache \
    build-base \
    cmake \
    openssl-dev \
    gtest-dev

WORKDIR /licenseseat-cpp
COPY . .

RUN cmake -B build -DLICENSESEAT_BUILD_TESTS=ON && cmake --build build

CMD ["./build/tests/licenseseat_tests"]
