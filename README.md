# PExplore

![Windows](https://img.shields.io/badge/platform-Windows-blue)
![C++](https://img.shields.io/badge/language-C++-brightgreen)
![Imgui](https://img.shields.io/badge/ui-Imgui-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

> PE file inspector and disassembler.

---

## Overview

`PExplore` is a lightweight GUI tool for inspecting and disassembling Windows Portable Executable files.

It provides a fast, minimal interface to explore:

* exports
* imports
* sections
* disassembled code

---

## Features

* open `.exe`, `.dll`, `.sys`, `.ocx`, `.efi`
* export table viewer with disassembly
* import tree (modules + functions)
* section viewer (flags, sizes, memory layout)
* fast symbol filtering
* drag & drop support
* simple disassembler view (colored, readable)

---

## Usage

Launch the application and:

* drag & drop a PE file
  **or**
* `File → Open`

then:

* Browse exports/imports/sections on the left
* Click an exported function to disassemble it

---

## Structure

* `PeParser` → parses PE headers and tables
* `Disassembler` → decodes instructions
* `App` → UI + interaction (ImGui)

---

## Screenshot

![PExplore in NTDLL](resources/image.png)

---

## philosophy

`pedump` is meant to be:

* small
* fast
* readable
* useful

not a full reverse engineering suite — just a solid tool.

---

## license

MIT