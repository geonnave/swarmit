#ifndef __VERSION_H
#define __VERSION_H

/**
 * @file
 * @brief Firmware version string, stamped at build time.
 *
 * `version_generated.h` is written by `scripts/gen-version.sh` as a SEGGER
 * pre-build step and is gitignored. This wrapper keeps the tree compiling when
 * that file is absent - a fresh clone before the first build, a tarball export
 * with no .git, a CI image without git, or an editor's clang index - so a
 * missing generated header degrades to "unknown" instead of failing the build.
 */

#if defined(__has_include)
#  if __has_include("version_generated.h")
#    include "version_generated.h"
#  endif
#endif

#ifndef SWRMT_FW_VERSION
#define SWRMT_FW_VERSION "unknown"
#endif

#endif
