# Eden Joy-Con fixes

Experimental community fixes for separate Joy-Con HD rumble and the right Joy-Con's built-in infrared camera in Eden v0.2.1 on Windows x64.

[Русская инструкция](README.ru.md) · [Validation and limitations](docs/validation.md)

The changes are in Eden's controller driver and IRS service, so they are not tied to a game ID. Testing has focused on **1-2-Switch with original Nintendo Joy-Con over Bluetooth**. Other games and every IR processing mode have not been verified.

## What changes

- A single left/right Joy-Con rejects vibration requests for its absent side, preventing both channels from reaching one motor.
- The output queue keeps the latest HD sample after a host/Bluetooth stall, preserving the existing frequency/amplitude encoder.
- Camera start/stop selects the player named by the camera handle instead of always selecting player 1.
- Configuration pauses also pause vibration output to the shared HID handle.
- Subcommand replies must match both the report type and requested command.
- IR setup gets up to three complete attempts, resetting the MCU between failed attempts.

The camera is the sensor inside the **right Joy-Con**. After installation, the fixes run when you launch Eden normally. Python is needed to apply the patch, not to play.

## Exact binary compatibility

The binary patcher supports the following Windows x64 executable hashes. Version text alone is insufficient.

| Executable | SHA256 |
|---|---|
| Original supported Eden v0.2.1 | `c4135c90e5dca07bfc629081ddfc316ad35ebe6095e54854706c61b41e98a97c` |
| Earlier rumble-only patch | `04f4dba6deb5cde35f0e1aecde1a3fab1cb6202befac863003ec85e7ebe2a945` |
| This combined patch | `4a3662eb69f43fc06079285a0b2567397b6a6d05b19a1cefc632d42117ec821c` |

Other executables are rejected. For other platforms/builds, review and build the C++ source patch against a compatible checkout instead of reusing binary addresses.

## Apply on Windows

Install Python 3.10 or newer, download this repository, then open PowerShell in its folder:

```powershell
python -m pip install -r requirements.txt
python patch_joycon.py "C:\Emulators\Eden\eden.exe" --check
python patch_joycon.py "C:\Emulators\Eden\eden.exe" "C:\Emulators\Eden\eden.fixed.exe" --manifest "local-results\manifest.json"
```

Replace the example emulator path with your own. The patcher creates a **separate file**, refuses existing output files, checks the final checksum, and leaves the input intact.

Close Eden. Keep a backup of the original `eden.exe`, then put the generated file in its place as `eden.exe` in the same Eden installation folder. Keep the installation's existing DLLs, plugins and configuration alongside it. Start Eden and your games normally.

Do not reapply after an Eden update without checking compatibility: an update can replace the executable. To roll back, close Eden and restore your original executable.

## Controller setup and acceptance

Use Eden's native Joy-Con driver and configure the physical controllers normally. The tested arrangement was a single left Joy-Con for player 1 and a single right Joy-Con for player 2. Enable vibration and Accurate Vibration for the rumble test.

In 1-2-Switch, check Ball Count with each controller separately. For IR, use Eating Contest with the right Joy-Con and follow the game's camera-position instructions. A blinking IR LED confirms activity, but successful mouth calibration/gameplay is a separate check.

Please report the exact Eden version/hash, OS, controller model, Bluetooth/USB connection, controller layout and affected game. Avoid posting keys, game files, camera frames or full unredacted device logs.

## Source patch

`patches/eden-v0.2.1-joycon-ir-and-rumble.patch` targets Eden tag `v0.2.1`, commit `58c1e20ee58efa3900ba616207d460886214480b` from the [upstream source repository](https://git.eden-emu.dev/eden-emu/eden).

From a clean compatible source checkout:

```powershell
git apply --check "C:\Path\To\eden-joycon-fixes\patches\eden-v0.2.1-joycon-ir-and-rumble.patch"
git apply "C:\Path\To\eden-joycon-fixes\patches\eden-v0.2.1-joycon-ir-and-rumble.patch"
```

Then follow upstream build instructions. A full C++ rebuild was not completed in the original test environment. The released binary patch is produced by the Python patchers; it is not represented as a newly compiled Eden build.

## Development and checks

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

The CLI safety tests do not require an emulator. Native x64 verification requires Windows x64 and your own compatible executable; see [validation](docs/validation.md). There is no service, database, credential configuration or background helper to deploy.

`patch_joycon.py` is the supported entry point. `patch_eden.py` and `patch_ir.py` are the two internal patch stages. PE changes preserve ASLR-compatible relative branches, maintain the checksum, and include unwind metadata for the added code fragments. See the validation report for the scope of verification.

## License and status

GPL-3.0-or-later. Upstream attribution and per-file notices remain in the source patch; see [NOTICE](NOTICE) and [LICENSE](LICENSE).

This is an independent experimental community patch, not an official Eden or Nintendo release. The repository contains patchers, source changes and test summaries. Broader game compatibility and exact original-Switch tactile fidelity remain unverified.
