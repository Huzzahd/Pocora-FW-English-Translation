"""Script that patches the Pocora .exe into english according to a TSV file.

This is presented for transparency, so users can patch the game themselves if they wish to, and is intended to be used
with a TSV file containing an english patch, used to overwrite the original japanese text.

However, it's not recommended to run this script with a TSV file that you do not trust. This script is not robust enough
security-wise and could be used, though with hardship, to patch the code segment of the .exe to run malicious code. The
intended patch file overwrites data only in the .rdata and .data segments of the original game's file, where the
original strings are stored.

This patcher is intended for version 1.301 of the game, however as it relies almost entirely on the TSV patch file, it
should work with other versions provided the patch file is accurate.

This only patches strings. Some text is embedded into image resources, which are patched manually through other means.
"""
# -- # Imports # ----------------------------------------------------------------------------------------------------- #
# Python
import csv
import pathlib as pl
import traceback
# Libraries
import colorama
from colorama import Fore, Back, Style

colorama.init()

# -- # Constants # --------------------------------------------------------------------------------------------------- #
PRS_PATH = pl.Path('prs.exe')
PATCH_PATH = pl.Path('patch.tsv')

OUT_PATH = pl.Path('prs_en.exe')

HDR_ADDR = 'Address'
HDR_HEX = 'Hex Contents'
HDR_SIZE = 'Max Sz'
HDR_DO_TL = 'TL?'
HDR_MODE = 'TL Mode'
HDR_TL = 'Translation'

HEADERS = {HDR_ADDR, HDR_HEX, HDR_SIZE, HDR_DO_TL, HDR_MODE, HDR_TL}

# -- # Script # ------------------------------------------------------------------------------------------------------ #
if __name__ == '__main__':
    try:
        if OUT_PATH.exists():
            print(
                Style.RESET_ALL +
                f"""Output file {Fore.MAGENTA + OUT_PATH.name + Fore.RESET} already exists at the target path:""",
                f"""> {Fore.YELLOW + str(OUT_PATH.resolve()) + Fore.RESET}""",
                f"""Please clear that file to ensure the script can save a new version.""",
                sep='\n'
            )

            exit(-1)
    except OSError as ex:
        print(
            Style.RESET_ALL +
            f"""Could not check if output file {Fore.YELLOW + OUT_PATH.name + Fore.RESET} already exists at the target path:""",
            f"""> {Fore.YELLOW + str(OUT_PATH.resolve()) + Fore.RESET}""",
            f"""Due to the following error:""",
            Fore.RED + "".join(traceback.format_exception(ex)) + Style.RESET_ALL,
            sep='\n'
        )

        exit(-1)

    try:
        prs_file = bytearray(PRS_PATH.read_bytes())
    except OSError as ex:
        try:
            print(
                Style.RESET_ALL +
                f"""Could not read game file to patch {Fore.MAGENTA + PRS_PATH.name + Fore.RESET} at the expected path:""",
                f"""> {Fore.YELLOW + str(PRS_PATH.resolve()) + Fore.RESET}""",
                f"""Due to the following error:""",
                Fore.RED + "".join(traceback.format_exception(ex)) + Style.RESET_ALL,
                sep='\n'
            )
        except OSError:
            print(
                Style.RESET_ALL +
                f"""Could not read game file to patch {Fore.MAGENTA + PRS_PATH.name + Fore.RESET} due to the following error:""",
                Fore.RED + "".join(traceback.format_exception(ex)) + Style.RESET_ALL,
                sep='\n'
            )

        exit(-1)

    try:
        patch_file = PATCH_PATH.read_text(encoding='utf-8', errors='strict')
    except (OSError, UnicodeDecodeError) as ex:
        try:
            print(
                Style.RESET_ALL +
                f"""Could not read patch file {Fore.MAGENTA + PATCH_PATH.name + Fore.RESET} at the expected path:""",
                f"""> {Fore.YELLOW + str(PATCH_PATH.resolve()) + Fore.RESET}""",
                f"""Due to the following error:""",
                Fore.RED + "".join(traceback.format_exception(ex)) + Style.RESET_ALL,
                sep='\n'
            )
        except OSError:
            print(
                Style.RESET_ALL +
                f"""Could not read patch file {Fore.MAGENTA + PATCH_PATH.name + Fore.RESET} due to the following error:""",
                Fore.RED + "".join(traceback.format_exception(ex)) + Style.RESET_ALL,
                sep='\n'
            )

        exit(-1)

    patch = csv.DictReader(
        patch_file.split('\n'),
        delimiter='\t',
        quoting=csv.QUOTE_NONE,
        strict=True
    )

    missing_headers = HEADERS - set(patch.fieldnames)
    if len(missing_headers) != 0:
        print(
            Style.RESET_ALL +
            f"""Patch header is missing one or more of the necessary columns:""",
            f"""> {", ".join(Fore.YELLOW + header + Fore.RESET for header in missing_headers)}""",
            sep='\n'
        )

        exit(-1)

    # Pre.
    changes_ready: list[tuple[int, bytes]] = []  # Address and bytestring.

    parsing_skips = 0
    parsing_successes = 0
    parsing_warnings = 0
    parsing_errors = 0

    # Iterate each row to figure out what needs to be patched and to validate too.
    for row_i, row in enumerate(patch):
        do_patch = row[HDR_DO_TL]
        patch_mode = row[HDR_MODE]
        patch_str = row[HDR_TL]

        # Check if this line needs to be replaced.
        if do_patch != 'Yes':
            parsing_skips += 1
            continue

        # Validate patch address.
        try:
            address = int(row[HDR_ADDR], 16)
        except ValueError:
            print(
                Style.RESET_ALL +
                Fore.RED + f"""ERROR (Line {row_i + 1}) - Invalid address: "{row[HDR_ADDR]}".""" + Fore.RESET
            )

            parsing_errors += 1
            continue
        else:
            address_str = '{:08X}'.format(address)

        # Validate patch size.
        try:
            patch_size = int(row[HDR_SIZE])
        except ValueError:
            print(
                Style.RESET_ALL +
                Fore.RED + f"""ERROR [{address_str}] - Invalid patch size: "{row[HDR_SIZE]}".""" + Fore.RESET
            )

            parsing_errors += 1
            continue

        # Validate patch raw contents.
        raw_bytes = prs_file[address:address + patch_size]

        try:
            expected_bytes = bytes.fromhex(row[HDR_HEX])
        except ValueError:
            print(
                Style.RESET_ALL +
                Fore.RED + f"""ERROR [{address_str}] - Invalid expected bytes.""" + Fore.RESET
            )

            parsing_errors += 1
            continue

        if len(expected_bytes) != patch_size:
            print(
                Style.RESET_ALL +
                Fore.RED + f"""ERROR [{address_str}] - Expected bytes don't match patch size.""" + Fore.RESET
            )

            parsing_errors += 1
            continue

        if raw_bytes != expected_bytes:
            print(
                Style.RESET_ALL +
                Fore.RED + f"ERROR [{address_str}] - Raw data does not match the expected bytes." + Fore.RESET
            )

            parsing_errors += 1
            continue

        # Check if patched string is properly terminated.
        first_nul_pos = raw_bytes.find(b'\x00') + 1

        if first_nul_pos == 0:
            print(
                Style.RESET_ALL +
                Fore.RED + f"""ERROR [{address_str}] - Raw data is not NUL terminated.""" + Fore.RESET,
            )

            parsing_errors += 1
            continue

        if any(byte != 0 for byte in raw_bytes[first_nul_pos:]):
            print(
                Style.RESET_ALL +
                Fore.RED + f"""ERROR [{address_str}] - Raw data encompasses multiple strings.""" + Fore.RESET,
            )

            parsing_errors += 1
            continue

        # Check if encoding is valid.
        if patch_mode == "Native":
            patch_enc = "1252"
        elif patch_mode == "Graphics":
            patch_enc = "Shift-JIS"
        else:
            print(
                Style.RESET_ALL +
                Fore.RED + f"""ERROR [{address_str}] - Invalid patch mode: {patch_mode}.""" + Fore.RESET,
            )

            parsing_errors += 1
            continue

        # Validate patch text.
        try:
            patch_bytes = patch_str.encode(patch_enc, errors='strict') + b'\x00'
        except UnicodeEncodeError:
            print(
                Style.RESET_ALL +
                Fore.RED + f"""ERROR [{address_str}] - Patch text could not be encoded properly.""" + Fore.RESET,
            )

            parsing_errors += 1
            continue

        if len(patch_bytes) > len(raw_bytes):
            print(
                Style.RESET_ALL +
                Fore.RED + f"""ERROR [{address_str}] - Patch text overflows the available space.""" + Fore.RESET
            )

            parsing_errors += 1
            continue

        if len(patch_bytes) > first_nul_pos:
            print(
                Style.RESET_ALL +
                Fore.YELLOW + f"WARNING [{address_str}] - Patch text is longer than the minimal raw string." + Fore.RESET
            )

            parsing_warnings += 1
        else:
            parsing_successes += 1

        changes_ready.append((address, patch_bytes))

    print(
        Style.RESET_ALL, f"""Pre-patch finished.""",
        f"""{parsing_skips} row(s) skipped.""",
        Fore.CYAN + f"""{parsing_successes} row(s) parsed successfully.""" + Fore.RESET,
        Fore.YELLOW + f"""{parsing_warnings} row(s) parsed with warnings.""" + Fore.RESET,
        Fore.RED + f"""{parsing_errors} row(s) could not be parsed.""" + Fore.RESET,
        sep='\n'
    )

    _ = input("Press any key to begin the patching process...")

    for address, contents in changes_ready:
        prs_file[address:address+len(contents)] = contents

    OUT_PATH.write_bytes(prs_file)

    print(Style.RESET_ALL + Fore.GREEN + "Patch finished successfully." + Fore.RESET)
