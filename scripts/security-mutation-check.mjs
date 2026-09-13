import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sandboxBase = resolve(homedir(), ".codex-build", "project15", "mutation-security");
const tsxCli = join(projectRoot, "node_modules", "tsx", "dist", "cli.mjs");

const policyMutations = [
  {
    id: "target.private-range-cannot-become-public",
    file: "target-range.ts",
    from: '    private: "private",',
    to: '    private: "public",'
  },
  {
    id: "target.unique-local-cannot-become-public",
    file: "target-range.ts",
    from: '    uniqueLocal: "private",',
    to: '    uniqueLocal: "public",'
  },
  {
    id: "target.loopback-cannot-become-public",
    file: "target-range.ts",
    from: '    loopback: "loopback",',
    to: '    loopback: "public",'
  },
  {
    id: "target.carrier-grade-cannot-become-public",
    file: "target-range.ts",
    from: '    carrierGradeNat: "carrier-grade",',
    to: '    carrierGradeNat: "public",'
  },
  {
    id: "target.link-local-cannot-become-public",
    file: "target-range.ts",
    from: '    linkLocal: "link-local",',
    to: '    linkLocal: "public",'
  },
  {
    id: "target.multicast-cannot-become-public",
    file: "target-range.ts",
    from: '    multicast: "multicast",',
    to: '    multicast: "public",'
  },
  {
    id: "target.unspecified-cannot-become-public",
    file: "target-range.ts",
    from: '    unspecified: "unspecified",',
    to: '    unspecified: "public",'
  },
  {
    id: "target.broadcast-cannot-become-public",
    file: "target-range.ts",
    from: '    broadcast: "broadcast",',
    to: '    broadcast: "public",'
  },
  {
    id: "target.reserved-cannot-become-public",
    file: "target-range.ts",
    from: '    reserved: "reserved"',
    to: '    reserved: "public"'
  },
  {
    id: "target.unknown-range-fails-closed",
    file: "target-range.ts",
    from: '  return mapping[range] ?? "reserved";',
    to: '  return mapping[range] ?? "public";'
  },
  {
    id: "target.rejects-padded-ipv4",
    file: "target.ts",
    from:
      '  if (octets.some((octet) => (octet.length > 1 && octet.startsWith("0")) || Number(octet) > 255)) {',
    to: '  if (octets.some((octet) => Number(octet) > 255)) {'
  },
  {
    id: "target.rejects-cidr",
    file: "target.ts",
    from: '    throw new TargetParseError("TARGET_CIDR_FORBIDDEN", "CIDR targets are not supported in the MVP");',
    to: '    return canonicalizeTarget(input.split("/", 1)[0]);'
  },
  {
    id: "target.rejects-ipv4-mapped-ipv6",
    file: "target.ts",
    from: "  if (address.isIPv4MappedAddress()) {",
    to: "  if (false) {"
  },
  {
    id: "policy.binds-proposal-to-mission",
    file: "policy.ts",
    from: "  if (proposal.missionId !== scope.missionId) {",
    to: "  if (false) {"
  },
  {
    id: "policy.enforces-authorization-window",
    file: "policy.ts",
    from: "  if (now < new Date(scope.startsAt) || now >= new Date(scope.expiresAt)) {",
    to: "  if (false) {"
  },
  {
    id: "policy.includes-start-boundary",
    file: "policy.ts",
    from: "  if (now < new Date(scope.startsAt) || now >= new Date(scope.expiresAt)) {",
    to: "  if (now <= new Date(scope.startsAt) || now >= new Date(scope.expiresAt)) {"
  },
  {
    id: "policy.excludes-expiry-boundary",
    file: "policy.ts",
    from: "  if (now < new Date(scope.startsAt) || now >= new Date(scope.expiresAt)) {",
    to: "  if (now < new Date(scope.startsAt) || now > new Date(scope.expiresAt)) {"
  },
  {
    id: "policy.binds-exact-target-id",
    file: "policy.ts",
    from: "  const target = resolveTarget(scope, proposal.targetId);",
    to: "  const target = scope.targets[0];"
  },
  {
    id: "policy.requires-private-isolation",
    file: "policy.ts",
    from: '    if (canonical.classification === "private" && !target.isolatedPrivateTargetApproved) {',
    to: "    if (false) {"
  },
  {
    id: "policy.denies-reserved-target-classes",
    file: "policy.ts",
    from: '    if (canonical.classification !== "public" && canonical.classification !== "private") {',
    to: "    if (false) {"
  },
  {
    id: "policy.enforces-capability-risk-tier",
    file: "policy.ts",
    from: "  if (proposal.riskTier !== expectedRisk) {",
    to: "  if (false) {"
  },
  {
    id: "policy.requires-fresh-t1-approval",
    file: "policy.ts",
    from: '      effect: "REQUIRE_APPROVAL",',
    to: '      effect: "ALLOW",'
  },
  {
    id: "scope.requires-unique-target-ids",
    file: "schemas.ts",
    from:
      '        (targets) => new Set(targets.map((target) => target.id)).size === targets.length,',
    to: "        () => true,"
  }
];

const executorContractMutations = [
  {
    id: "approval.validates-proposal-digest",
    file: "validate.ts",
    from: "  if (digestProposal(request.proposal) !== request.proposalDigest) {",
    to: "  if (false) {"
  },
  {
    id: "approval.validates-approval-digest",
    file: "validate.ts",
    from: "  if (digestApproval(request.approval) !== request.approvalDigest) {",
    to: "  if (false) {"
  },
  {
    id: "approval.binds-proposal-digest",
    file: "validate.ts",
    from: "    request.approval.proposalDigest !== request.proposalDigest ||",
    to: "    false ||"
  },
  {
    id: "approval.binds-resolved-target-and-limits",
    file: "validate.ts",
    from: "  if (request.approval.executionBindingDigest !== digestExecutionBinding({",
    to: "  if (false && request.approval.executionBindingDigest !== digestExecutionBinding({"
  },
  {
    id: "approval.binds-mission",
    file: "validate.ts",
    from: "    request.approval.missionId !== request.proposal.missionId ||",
    to: "    false ||"
  },
  {
    id: "approval.binds-target",
    file: "validate.ts",
    from: "    request.approval.targetId !== request.proposal.targetId ||",
    to: "    false ||"
  },
  {
    id: "approval.binds-capability",
    file: "validate.ts",
    from: "    request.approval.capabilityId !== request.proposal.capabilityId",
    to: "    false"
  },
  {
    id: "approval.expires-at-exact-boundary",
    file: "validate.ts",
    from: "  if (Date.parse(request.approval.expiresAt) <= now.getTime()) {",
    to: "  if (Date.parse(request.approval.expiresAt) < now.getTime()) {"
  },
  {
    id: "approval.binds-resolved-target",
    file: "validate.ts",
    from: "  if (request.target.targetId !== request.proposal.targetId) {",
    to: "  if (false) {"
  },
  {
    id: "request.rejects-unknown-fields",
    file: "schemas.ts",
    from: "  submittedAt: isoDateSchema\n}).strict();",
    to: "  submittedAt: isoDateSchema\n}).passthrough();"
  },
  {
    id: "approval.declares-single-use",
    file: "schemas.ts",
    from: "  maxUses: z.literal(1)",
    to: "  maxUses: z.number().int().positive()"
  },
  {
    id: "target.resolution-remains-backend-owned",
    file: "schemas.ts",
    from: '  resolutionSource: z.literal("scope-registry"),',
    to: '  resolutionSource: z.enum(["scope-registry", "model"]),'
  },
  {
    id: "target.address-family-must-match",
    file: "schemas.ts",
    from: "  if (target.addressFamily !== expected) {",
    to: "  if (false) {"
  },
  {
    id: "output.chunk-size-remains-bounded",
    file: "schemas.ts",
    from: "export const MAX_OUTPUT_CHUNK_BYTES = 16_384;",
    to: "export const MAX_OUTPUT_CHUNK_BYTES = 32_768;"
  },
  {
    id: "output.byte-count-must-match",
    file: "schemas.ts",
    from: '  if (Buffer.byteLength(chunk.content, "utf8") !== chunk.contentBytes) {',
    to: "  if (false) {"
  },
  {
    id: "limits.timeout-remains-bounded",
    file: "schemas.ts",
    from: "  timeoutMs: z.number().int().min(100).max(120_000),",
    to: "  timeoutMs: z.number().int().min(100).max(240_000),"
  },
  {
    id: "limits.output-remains-bounded",
    file: "schemas.ts",
    from: "  maxOutputBytes: z.number().int().min(1).max(1_000_000),",
    to: "  maxOutputBytes: z.number().int().min(1).max(2_000_000),"
  },
  {
    id: "limits.evidence-remains-bounded",
    file: "schemas.ts",
    from: "  maxEvidenceBytes: z.number().int().min(1).max(5_000_000)",
    to: "  maxEvidenceBytes: z.number().int().min(1).max(10_000_000)"
  },
  {
    id: "executor.validates-expiry-at-current-time",
    file: "nmap-tcp-executor.ts",
    from: "    const invocation = compileNmapTcpInvocation(request, this.config, startedAt);",
    to: "    const invocation = compileNmapTcpInvocation(request, this.config, new Date(request.submittedAt));"
  },
  {
    id: "executor.enforces-combined-output-limit",
    file: "nmap-tcp-executor.ts",
    from: "        if (next.byteLength > limit || totalOutputBytes + bytes.byteLength > request.limits.maxOutputBytes) {",
    to: "        if (next.byteLength > limit) {"
  },
  {
    id: "adapter.remains-disabled-by-default",
    file: "nmap-tcp-adapter.ts",
    from: "  if (!config.executionEnabled) {",
    to: "  if (false) {"
  },
  {
    id: "adapter.requires-verified-isolation-before-enable",
    file: "nmap-tcp-adapter.ts",
    from: "  if (config.executionEnabled &&\n      (!config.isolation.verified ||",
    to: "  if (false &&\n      (!config.isolation.verified ||"
  },
  {
    id: "adapter.binds-exact-isolated-address",
    file: "nmap-tcp-adapter.ts",
    from: "  if (request.target.canonicalAddress !== config.isolation.exactTargetAddress) {",
    to: "  if (false) {"
  },
  {
    id: "adapter.never-uses-shell",
    file: "nmap-tcp-adapter.ts",
    from: "    spawnOptions: { shell: false, windowsHide: true },",
    to: "    spawnOptions: { shell: true, windowsHide: true },"
  },
  {
    id: "pack.rejects-unknown-code-fields",
    file: "capability-pack.ts",
    from:
      '  evidenceMediaTypes: z.array(z.enum(["application/json", "text/plain"])).min(1).max(2)\n}).strict().superRefine((manifest, context) => {',
    to:
      '  evidenceMediaTypes: z.array(z.enum(["application/json", "text/plain"])).min(1).max(2)\n}).passthrough().superRefine((manifest, context) => {'
  },
  {
    id: "pack.remains-nondestructive",
    file: "capability-pack.ts",
    from: "  destructive: z.literal(false),",
    to: "  destructive: z.boolean(),"
  },
  {
    id: "pack.denies-credential-access",
    file: "capability-pack.ts",
    from: "    credentialAccess: z.literal(false),",
    to: "    credentialAccess: z.boolean(),"
  },
  {
    id: "pack.denies-payload-execution",
    file: "capability-pack.ts",
    from: "    payloadExecution: z.literal(false),",
    to: "    payloadExecution: z.boolean(),"
  },
  {
    id: "pack.denies-evasion-controls",
    file: "capability-pack.ts",
    from: "    evasionControls: z.literal(false)",
    to: "    evasionControls: z.boolean()"
  },
  {
    id: "pack.permissions-reject-unknown-fields",
    file: "capability-pack.ts",
    from: "    evasionControls: z.literal(false)\n  }).strict(),",
    to: "    evasionControls: z.literal(false)\n  }).passthrough(),"
  },
  {
    id: "pack.timeout-remains-bounded",
    file: "capability-pack.ts",
    from: "    timeoutMs: z.number().int().min(100).max(120_000),",
    to: "    timeoutMs: z.number().int().min(100).max(240_000),"
  },
  {
    id: "pack.output-remains-bounded",
    file: "capability-pack.ts",
    from: "    maxOutputBytes: z.number().int().min(1).max(1_000_000),",
    to: "    maxOutputBytes: z.number().int().min(1).max(2_000_000),"
  },
  {
    id: "pack.evidence-remains-bounded",
    file: "capability-pack.ts",
    from: "    maxEvidenceBytes: z.number().int().min(1).max(5_000_000),",
    to: "    maxEvidenceBytes: z.number().int().min(1).max(10_000_000),"
  },
  {
    id: "pack.request-count-remains-bounded",
    file: "capability-pack.ts",
    from: "    maxRequests: z.number().int().min(1).max(16)",
    to: "    maxRequests: z.number().int().min(1).max(32)"
  },
  {
    id: "pack.limits-reject-unknown-fields",
    file: "capability-pack.ts",
    from: "    maxRequests: z.number().int().min(1).max(16)\n  }).strict(),",
    to: "    maxRequests: z.number().int().min(1).max(16)\n  }).passthrough(),"
  },
  {
    id: "pack.keeps-t0-offline",
    file: "capability-pack.ts",
    from: '  if (manifest.riskTier === "T0" &&',
    to: "  if (false &&"
  },
  {
    id: "pack.exact-target-requires-approval",
    file: "capability-pack.ts",
    from: '  if (manifest.permissions.network === "exact-target" &&',
    to: "  if (false &&"
  },
  {
    id: "pack.target-requires-exact-network",
    file: "capability-pack.ts",
    from: '  if (manifest.targetRequired && manifest.permissions.network !== "exact-target") {',
    to: "  if (false) {"
  }
];

const mutationSuites = [
  {
    suite: "policy-security-boundary-v1",
    packagePath: "packages/policy",
    mutations: policyMutations
  },
  {
    suite: "executor-contract-security-boundary-v1",
    packagePath: "packages/executor-contract",
    mutations: executorContractMutations
  }
];

function isContainedPath(root, candidate) {
  const relativePath = relative(root, candidate);
  return (
    relativePath !== "" &&
    relativePath !== ".." &&
    !relativePath.startsWith(`..${sep}`) &&
    !isAbsolute(relativePath)
  );
}

function canonicalDefinitionKey(value) {
  return process.platform === "win32" ? value.toLowerCase() : value;
}

function validateMutationSuites() {
  if (!Array.isArray(mutationSuites) || mutationSuites.length === 0) {
    throw new Error("At least one mutation suite is required");
  }

  const suiteNames = new Set();
  const packageRoots = new Set();
  const mutationIds = new Set();
  const mutationDefinitions = new Set();
  const packagesRoot = resolve(projectRoot, "packages");

  for (const definition of mutationSuites) {
    if (
      typeof definition.suite !== "string" ||
      definition.suite.trim().length === 0 ||
      typeof definition.packagePath !== "string" ||
      definition.packagePath.trim().length === 0
    ) {
      throw new Error("Mutation suites require non-empty suite and packagePath values");
    }

    const suiteKey = canonicalDefinitionKey(definition.suite);
    if (suiteNames.has(suiteKey)) {
      throw new Error(`Duplicate mutation suite: ${definition.suite}`);
    }
    suiteNames.add(suiteKey);

    const sourcePackageRoot = resolve(
      projectRoot,
      ...definition.packagePath.split("/")
    );
    if (!isContainedPath(packagesRoot, sourcePackageRoot)) {
      throw new Error(
        `Mutation suite ${definition.suite} package is outside the packages root`
      );
    }
    const packageKey = canonicalDefinitionKey(sourcePackageRoot);
    if (packageRoots.has(packageKey)) {
      throw new Error(
        `Duplicate mutation package root: ${definition.packagePath}`
      );
    }
    packageRoots.add(packageKey);

    if (!Array.isArray(definition.mutations) || definition.mutations.length === 0) {
      throw new Error(`Mutation suite ${definition.suite} must not be empty`);
    }

    for (const mutation of definition.mutations) {
      if (
        typeof mutation.id !== "string" ||
        mutation.id.trim().length === 0 ||
        typeof mutation.file !== "string" ||
        mutation.file.trim().length === 0 ||
        typeof mutation.from !== "string" ||
        mutation.from.trim().length === 0 ||
        typeof mutation.to !== "string" ||
        mutation.to.trim().length === 0 ||
        mutation.from === mutation.to
      ) {
        throw new Error(
          `Mutation suite ${definition.suite} contains an invalid mutation definition`
        );
      }

      const mutationId = canonicalDefinitionKey(mutation.id);
      if (mutationIds.has(mutationId)) {
        throw new Error(`Duplicate mutation id: ${mutation.id}`);
      }
      mutationIds.add(mutationId);

      const sourceFile = resolve(sourcePackageRoot, "src", mutation.file);
      if (!isContainedPath(resolve(sourcePackageRoot, "src"), sourceFile)) {
        throw new Error(
          `Mutation ${definition.suite}/${mutation.id} is outside the package source root`
        );
      }
      const definitionKey = [
        packageKey,
        canonicalDefinitionKey(sourceFile),
        mutation.from,
        mutation.to
      ].join("\0");
      if (mutationDefinitions.has(definitionKey)) {
        throw new Error(
          `Duplicate mutation definition: ${definition.suite}/${mutation.id}`
        );
      }
      mutationDefinitions.add(definitionKey);
    }
  }
}

function portablePath(value) {
  return value.split(sep).join("/");
}

async function captureTree(root, snapshotRoot, relativeRoot, snapshot) {
  const entries = await readdir(join(root, relativeRoot), {
    withFileTypes: true
  });
  entries.sort((left, right) => left.name.localeCompare(right.name, "en"));

  const directoryKey = portablePath(join(snapshotRoot, relativeRoot));
  snapshot.directories.add(directoryKey);

  for (const entry of entries) {
    const relativeEntry = join(relativeRoot, entry.name);
    if (entry.isDirectory()) {
      await captureTree(root, snapshotRoot, relativeEntry, snapshot);
      continue;
    }
    if (!entry.isFile()) {
      throw new Error(
        `Mutation snapshot input is not a regular file: ${join(root, relativeEntry)}`
      );
    }

    const key = portablePath(join(snapshotRoot, relativeEntry));
    if (snapshot.files.has(key)) {
      throw new Error(`Duplicate mutation snapshot file: ${key}`);
    }
    snapshot.files.set(key, await readFile(join(root, relativeEntry)));
  }
}

async function captureAuthoritativeSnapshot() {
  const snapshot = {
    directories: new Set(),
    files: new Map()
  };
  snapshot.files.set(
    "tsconfig.base.json",
    await readFile(join(projectRoot, "tsconfig.base.json"))
  );

  for (const definition of mutationSuites) {
    const sourcePackageRoot = resolve(
      projectRoot,
      ...definition.packagePath.split("/")
    );
    await captureTree(
      sourcePackageRoot,
      definition.packagePath,
      "",
      snapshot
    );
  }
  return snapshot;
}

async function materializeSnapshot(runRoot, snapshot) {
  const directories = [...snapshot.directories].sort();
  for (const directory of directories) {
    await mkdir(join(runRoot, ...directory.split("/")), {
      recursive: true
    });
  }
  for (const [file, content] of snapshot.files) {
    const destination = join(runRoot, ...file.split("/"));
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, content);
  }
}

function snapshotsEqual(expected, actual) {
  if (
    expected.directories.size !== actual.directories.size ||
    expected.files.size !== actual.files.size
  ) {
    return false;
  }
  for (const directory of expected.directories) {
    if (!actual.directories.has(directory)) {
      return false;
    }
  }
  for (const [file, content] of expected.files) {
    const actualContent = actual.files.get(file);
    if (!actualContent || !content.equals(actualContent)) {
      return false;
    }
  }
  return true;
}

async function assertSourceUnchanged(expected) {
  let actual;
  try {
    actual = await captureAuthoritativeSnapshot();
  } catch (error) {
    throw new Error(
      `Mutation source drift detected: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error }
    );
  }
  if (!snapshotsEqual(expected, actual)) {
    throw new Error("Mutation source drift detected while the suites were running");
  }
}

function countOccurrences(value, search) {
  return value.split(search).length - 1;
}

function boundedDiagnostic(result) {
  const combined = `${result.stdout ?? ""}\n${result.stderr ?? ""}`
    .replaceAll("\r", "")
    .trim();
  if (combined.length <= 1_600) {
    return combined;
  }
  return `${combined.slice(0, 800)}\n...\n${combined.slice(-800)}`;
}

function runPackageTests(sandboxPackageRoot, testFiles) {
  return spawnSync(
    process.execPath,
    [tsxCli, "--test", ...testFiles],
    {
      cwd: sandboxPackageRoot,
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
      maxBuffer: 1024 * 1024,
      shell: false,
      timeout: 60_000,
      windowsHide: true
    }
  );
}

async function restoreSources(sandboxSourceRoot, originals) {
  await Promise.all(
    [...originals].map(([file, content]) =>
      writeFile(join(sandboxSourceRoot, file), content, "utf8")
    )
  );
}

async function runMutationSuite(runRoot, definition) {
  const sandboxPackageRoot = join(runRoot, ...definition.packagePath.split("/"));
  const sandboxSourceRoot = join(sandboxPackageRoot, "src");

  const testFiles = (await readdir(sandboxSourceRoot))
    .filter((file) => file.endsWith(".test.ts"))
    .sort()
    .map((file) => join(sandboxSourceRoot, file));
  if (testFiles.length === 0) {
    throw new Error(`Mutation suite ${definition.suite} has no test files`);
  }

  const mutatedFiles = [...new Set(definition.mutations.map((mutation) => mutation.file))];
  const originals = new Map(
    await Promise.all(
      mutatedFiles.map(async (file) => [
        file,
        await readFile(join(sandboxSourceRoot, file), "utf8")
      ])
    )
  );

  const baseline = runPackageTests(sandboxPackageRoot, testFiles);
  if (
    baseline.error ||
    baseline.signal !== null ||
    !Number.isInteger(baseline.status) ||
    baseline.status !== 0
  ) {
    const detail = baseline.error?.message ?? boundedDiagnostic(baseline);
    throw new Error(`Mutation baseline ${definition.suite} failed: ${detail}`);
  }

  const results = [];
  for (const mutation of definition.mutations) {
    await restoreSources(sandboxSourceRoot, originals);
    const original = originals.get(mutation.file);
    const reviewedSource = original.replaceAll("\r\n", "\n");
    if (countOccurrences(reviewedSource, mutation.from) !== 1) {
      throw new Error(
        `Mutation ${definition.suite}/${mutation.id} no longer matches exactly one reviewed source location`
      );
    }

    const mutatedSource = reviewedSource.replace(mutation.from, mutation.to);

    await writeFile(
      join(sandboxSourceRoot, mutation.file),
      original.includes("\r\n") ? mutatedSource.replaceAll("\n", "\r\n") : mutatedSource,
      "utf8"
    );

    const result = runPackageTests(sandboxPackageRoot, testFiles);
    if (result.error || result.signal !== null || !Number.isInteger(result.status)) {
      const detail = result.error?.message ?? result.signal ?? boundedDiagnostic(result);
      throw new Error(`Mutation ${definition.suite}/${mutation.id} ended abnormally: ${detail}`);
    }
    results.push({
      id: mutation.id,
      killed: result.status !== 0,
      outcome: result.status === 0 ? "survived" : "test-failure"
    });
  }

  const survived = results.filter((result) => !result.killed).map((result) => result.id);
  return {
    suite: definition.suite,
    baselinePassed: true,
    mutationCount: results.length,
    killedCount: results.length - survived.length,
    survived,
    allMutationsKilled: survived.length === 0
  };
}

async function main() {
  validateMutationSuites();
  const sourceSnapshot = await captureAuthoritativeSnapshot();
  await mkdir(sandboxBase, { recursive: true });
  const runRoot = await mkdtemp(join(sandboxBase, "run-"));
  const allowedPrefix = `${sandboxBase}${sep}`.toLowerCase();
  if (!runRoot.toLowerCase().startsWith(allowedPrefix)) {
    throw new Error("Refusing to use a mutation sandbox outside the approved build root");
  }

  try {
    await materializeSnapshot(runRoot, sourceSnapshot);
    await symlink(
      join(projectRoot, "node_modules"),
      join(runRoot, "node_modules"),
      process.platform === "win32" ? "junction" : "dir"
    );

    const suites = [];
    for (const definition of mutationSuites) {
      suites.push(await runMutationSuite(runRoot, definition));
    }
    await assertSourceUnchanged(sourceSnapshot);
    const mutationCount = suites.reduce((sum, suite) => sum + suite.mutationCount, 0);
    const killedCount = suites.reduce((sum, suite) => sum + suite.killedCount, 0);
    const allMutationsKilled =
      suites.length === mutationSuites.length &&
      suites.length > 0 &&
      mutationCount > 0 &&
      killedCount === mutationCount &&
      suites.every(
        (suite) =>
          suite.baselinePassed &&
          suite.mutationCount > 0 &&
          suite.killedCount === suite.mutationCount &&
          suite.allMutationsKilled
      );
    const summary = {
      schemaVersion: 2,
      suites,
      mutationCount,
      killedCount,
      allMutationsKilled
    };
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);

    if (!allMutationsKilled) {
      process.exitCode = 1;
    }
  } finally {
    const resolvedRunRoot = resolve(runRoot);
    if (
      resolvedRunRoot.toLowerCase().startsWith(allowedPrefix) &&
      resolvedRunRoot.toLowerCase() !== sandboxBase.toLowerCase()
    ) {
      await rm(resolvedRunRoot, { recursive: true, force: true });
    }
  }
}

await main();
