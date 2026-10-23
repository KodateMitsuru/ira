// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <algorithm>
#include <memory>
#include <span>

#include <android-base/logging.h>


#include "types.h"

enum class DecodeResult {
    Error,
    Done,
    NeedInput,
    MoreOutput,
};

enum class EncodeResult {
    Error,
    Done,
    NeedInput,
    MoreOutput,
};

struct Decoder {
    void Append(Block&& block) { input_buffer_.append(std::move(block)); }
    bool Finish() {
        bool old = std::exchange(finished_, true);
        if (old) {
            LOG(FATAL) << "Decoder::Finish called while already finished?";
            return false;
        }
        return true;
    }

    virtual DecodeResult Decode(std::span<char>* output) = 0;

  protected:
    Decoder(std::span<char> output_buffer) : output_buffer_(output_buffer) {}
    ~Decoder() = default;

    bool finished_ = false;
    IOVector input_buffer_;
    std::span<char> output_buffer_;
};

struct Encoder {
    void Append(Block input) { input_buffer_.append(std::move(input)); }
    bool Finish() {
        bool old = std::exchange(finished_, true);
        if (old) {
            LOG(FATAL) << "Decoder::Finish called while already finished?";
            return false;
        }
        return true;
    }

    virtual EncodeResult Encode(Block* output) = 0;

  protected:
    explicit Encoder(size_t output_block_size) : output_block_size_(output_block_size) {}
    ~Encoder() = default;

    const size_t output_block_size_;
    bool finished_ = false;
    IOVector input_buffer_;
};

struct NullDecoder final : public Decoder {
    explicit NullDecoder(std::span<char> output_buffer) : Decoder(output_buffer) {}

    DecodeResult Decode(std::span<char>* output) final {
        size_t available_out = output_buffer_.size();
        void* p = output_buffer_.data();
        while (available_out > 0 && !input_buffer_.empty()) {
            size_t len = std::min(available_out, input_buffer_.front_size());
            p = mempcpy(p, input_buffer_.front_data(), len);
            available_out -= len;
            input_buffer_.drop_front(len);
        }
        *output = std::span(output_buffer_.data(), static_cast<char*>(p));
        if (input_buffer_.empty()) {
            return finished_ ? DecodeResult::Done : DecodeResult::NeedInput;
        }
        return DecodeResult::MoreOutput;
    }
};

struct NullEncoder final : public Encoder {
    explicit NullEncoder(size_t output_block_size) : Encoder(output_block_size) {}

    EncodeResult Encode(Block* output) final {
        output->clear();
        output->resize(output_block_size_);

        size_t available_out = output->size();
        void* p = output->data();

        while (available_out > 0 && !input_buffer_.empty()) {
            size_t len = std::min(available_out, input_buffer_.front_size());
            p = mempcpy(p, input_buffer_.front_data(), len);
            available_out -= len;
            input_buffer_.drop_front(len);
        }

        output->resize(output->size() - available_out);

        if (input_buffer_.empty()) {
            return finished_ ? EncodeResult::Done : EncodeResult::NeedInput;
        }
        return EncodeResult::MoreOutput;
    }
};
