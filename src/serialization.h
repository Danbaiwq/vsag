
// Copyright 2024-present the vsag project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <memory>
#include <string>

#include "stream_reader.h"
#include "stream_writer.h"
#include "typing.h"

namespace vsag {

// Metadata is using to describe how is the index create
class Metadata;
using MetadataPtr = std::shared_ptr<Metadata>;
class Metadata {
public:
    Metadata() = default;
    ~Metadata() = default;

    std::string
    Dump() {
        return metadata_.dump();
    }

private:
    JsonType metadata_;
};

// Footer is a wrapper of metadata, only used in all-in-one serialize format
class Footer;
using FooterPtr = std::shared_ptr<Footer>;
class Footer {
public:
    static FooterPtr
    Parse(StreamReader& reader) {
        return std::make_shared<Footer>();
    }

    void
    Write(StreamWriter& writer) {
        const std::string magic_num = "abcdefgh";
        writer.Write(magic_num.c_str(), 8);
        StreamWriter::WriteString(writer, metadata_->Dump());
        writer.Write(magic_num.c_str(), 8);
    }

public:
    Footer() = default;
    ~Footer() = default;

private:
    MetadataPtr metadata_;
};

};  // namespace vsag

// namespace vsag
