#pragma once

#include <exception>

// Kept distinct from runtime_error so carrier probing cannot mistake a
// cancellation for an ordinary non-carrier JPEG. The FFI catches it after
// native guards unwind, and Rust re-raises its pending signal after cleanup.
class SignalCancellation final : public std::exception {
public:
    explicit SignalCancellation(int signal_number) noexcept
        : signal_number_(signal_number) {}

    [[nodiscard]] int signalNumber() const noexcept { return signal_number_; }
    [[nodiscard]] const char* what() const noexcept override {
        return "Operation interrupted by signal";
    }

private:
    int signal_number_;
};

// C callbacks must return to C++ before any exception unwinds.
[[nodiscard]] int pendingSignalCancellation() noexcept;
void throwIfSignalCancellationRequested();
