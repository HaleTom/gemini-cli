/**
 * @license
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import os from 'node:os';
import {
  type SandboxManager,
  NoopSandboxManager,
  LocalSandboxManager,
  type GlobalSandboxOptions,
} from './sandboxManager.js';
import { LinuxSandboxManager } from '../sandbox/linux/LinuxSandboxManager.js';
import { MacOsSandboxManager } from '../sandbox/macos/MacOsSandboxManager.js';
import { WindowsSandboxManager } from '../sandbox/windows/WindowsSandboxManager.js';
import type { SandboxConfig } from '../config/config.js';

/**
 * Creates a sandbox manager based on the provided settings.
 */
export function createSandboxManager(
  sandbox: SandboxConfig | undefined,
  options: GlobalSandboxOptions,
  approvalMode?: string,
): SandboxManager {
  if (approvalMode === 'yolo') {
    return new NoopSandboxManager();
  }

  const modeConfig =
    options.modeConfig ??
    (options.policyManager && approvalMode
      ? options.policyManager.getModeConfig(approvalMode)
      : undefined);

  if (sandbox?.enabled) {
    const sandboxOptions = { ...options, modeConfig };
    if (os.platform() === 'win32') {
      return new WindowsSandboxManager(sandboxOptions);
    } else if (os.platform() === 'linux') {
      return new LinuxSandboxManager(sandboxOptions);
    } else if (os.platform() === 'darwin') {
      return new MacOsSandboxManager(sandboxOptions);
    }
    return new LocalSandboxManager(options);
  }

  return new NoopSandboxManager(options);
}
