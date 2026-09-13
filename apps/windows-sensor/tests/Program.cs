using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging.Abstractions;
using WARRoom.WindowsSensor;
using WARRoom.WindowsSensor.AuditWitnessInstaller;
using WARRoom.WindowsSensor.Readiness;

var tests = new (string Name, Action Run)[]
{
    ("accepts the exact non-exportable Software KSP machine-key metadata", AcceptsExactNativeKey),
    ("rejects a current-user key", () => RejectsKey(key => key with { IsMachineKey = false })),
    ("rejects an exportable key", () => RejectsKey(key => key with { ExportPolicy = CngExportPolicies.AllowExport })),
    ("rejects an unvalidated TPM-provider substitution", () => RejectsKey(key => key with { ProviderName = SensorBoundary.ExperimentalPlatformProviderName })),
    ("rejects a non-P256 algorithm", () => RejectsKey(key => key with { Algorithm = CngAlgorithm.ECDsaP384.Algorithm, KeySize = 384 })),
    ("accepts the exact protected LocalService read-only ACL", AcceptsExactProtectedAcl),
    ("accepts Software KSP normalized ACL masks", AcceptsSoftwareKspNormalizedAcl),
    ("rejects an unprotected ACL", () => RejectsAcl("O:BAG:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;LS)")),
    ("rejects an inherited ACL entry", () => RejectsAcl("O:BAG:BAD:P(A;ID;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;LS)")),
    ("rejects an unknown ACL principal", () => RejectsAcl("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;LS)(A;;GR;;;BU)")),
    ("rejects writable LocalService access", () => RejectsAcl("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GW;;;LS)")),
    ("rejects a non-administrator ACL owner", () => RejectsAcl("O:SYG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;LS)")),
    ("freezes the source-only service SID hardening plan", ValidatesServiceSidHardeningPlan),
    ("resolves only the fixed unrestricted Windows service SID", ValidatesServiceSidAuthority),
    ("accepts only the service SID on the v2 key ACL", ValidatesServiceSidKeyAcl),
    ("rejects service SID authority and ordering drift", RejectsServiceSidHardeningDrift),
    ("applies and reads back the fixed unrestricted service SID", AppliesUnrestrictedServiceSid),
    ("does not rewrite an already unrestricted service SID", KeepsUnrestrictedServiceSid),
    ("recovers the original service SID type after apply drift", RecoversServiceSidAfterApplyDrift),
    ("restores and reads back the exact previous service SID type", RestoresPreviousServiceSidType),
    ("rejects invalid service SID configuration authority", RejectsServiceSidConfigurationDrift),
    ("validates service SID status through the full native authority", ValidatesServiceSidStatusAuthority),
    ("exposes only fixed service SID tool commands", ValidatesServiceSidToolCommands),
    ("creates and advances an externally anchored audit head", ValidatesAuditHeadCheckpoint),
    ("rejects audit-head forks gaps and rollback", RejectsAuditHeadContinuityDrift),
    ("rejects audit-head signer and checkpoint tampering", RejectsAuditHeadSignerDrift),
    ("does not advance audit-head state after commit failure", RejectsAuditHeadCommitFailure),
    ("matches the shared audit-witness PREPARE and COMMIT vectors", MatchesAuditWitnessWireVectors),
    ("orders durable audit-witness PREPARE before bound COMMIT", ValidatesAuditWitnessPhaseOrder),
    ("classifies audit-witness crash recovery without inventing history", ValidatesAuditWitnessRecovery),
    ("rejects audit-witness fork gap replay and binding drift", RejectsAuditWitnessDrift),
    ("freezes the source-only protected audit-witness append plan", ValidatesAuditWitnessAppendPlan),
    ("freezes the sealed protected audit-witness installer plan", ValidatesAuditWitnessProtectedInstallerPlan),
    ("freezes the non-writing standard-user append authority proof", ValidatesAuditWitnessEffectiveAccessPlan),
    ("accepts only the exact audit-witness root and file ACLs", ValidatesAuditWitnessAppendAcls),
    ("rejects writable replaceable or unknown audit-witness ACL authority", RejectsAuditWitnessAppendAclDrift),
    ("rejects unsafe audit-witness append file shapes", RejectsAuditWitnessAppendShapeDrift),
    ("freezes the dedicated native audit-head writer boundary", ValidatesNativeAuditHeadWriterPlan),
    ("provisions only the distinct protected audit-head key", ProvisionsNativeAuditHeadWriterKey),
    ("rejects unsafe audit-head key ACL metadata and export", RejectsNativeAuditHeadWriterKeyDrift),
    ("checkpoints only one strict fixed pending continuity proof", ValidatesNativeAuditHeadWriterCheckpoint),
    ("rejects malformed pending proof and checkpoint replay", RejectsNativeAuditHeadPendingDrift),
    ("rejects unsafe audit-head pending and state file authority", RejectsNativeAuditHeadFileDrift),
    ("provisioning plan has no replacement or command authority", ValidatesProvisioningPlan),
    ("provisioner parser exposes only reviewed identity commands", ValidatesProvisionerCommands),
    ("signs only an exact short-lived enrollment challenge", SignsExactEnrollmentChallenge),
    ("rejects enrollment challenge schema, binding and time drift", RejectsEnrollmentChallengeDrift),
    ("self-verifies the enrollment proof before returning it", RejectsCorruptEnrollmentProof),
    ("creates an exact blocked pending endpoint binding", ValidatesPendingEndpointBinding),
    ("creates one signed read-access capability proof", ValidatesEndpointCapabilityProof),
    ("rejects capability authority and binding drift", RejectsEndpointCapabilityDrift),
    ("finalizes only the exact blocked capability binding", FinalizesEndpointBinding),
    ("rejects malformed and rebound endpoint bindings", RejectsEndpointBindingDrift),
    ("writes a capability proof exactly once across service starts", WritesCapabilityProofOnce),
    ("missing-key status is read-only", ReadsMissingStatusWithoutOpening),
    ("valid-key status verifies policy without deleting", ReadsValidStatusWithoutDeleting),
    ("status fails closed when private export is possible", RejectsExportableStatusWithoutDeleting),
    ("provisioning refuses an existing identity without mutation", RefusesExistingIdentity),
    ("successful provisioning proves signing and retains the new identity", ProvisionsAndRetainsValidIdentity),
    ("failed validation deletes only the identity created by that attempt", DeletesCreatedIdentityAfterFailure),
    ("failed non-exportability proof deletes only the created identity", DeletesCreatedIdentityWhenExportIsPossible),
    ("failed signing proof deletes only the identity created by that attempt", DeletesCreatedIdentityAfterBadProof),
    ("diagnostic probe plan cannot delete the production identity", ValidatesDiagnosticProbePlan),
    ("diagnostic probe status is read-only", ReadsDiagnosticProbeStatus),
    ("missing diagnostic probe cleanup is idempotent", CleansMissingDiagnosticProbe),
    ("exact diagnostic probe cleanup deletes only that probe", CleansExactDiagnosticProbe),
    ("diagnostic probe cleanup rejects metadata drift", RejectsDiagnosticProbeDrift),
    ("emits fixed-width P1363 signatures compatible with the API profile", VerifiesNativeSignatureProfile),
    ("creates and verifies the LocalService startup signing proof", VerifiesLocalServiceStartupProof),
    ("rejects a corrupt LocalService startup signing proof", RejectsCorruptLocalServiceStartupProof),
    ("matches the shared minimized-fact wire vector", MatchesMinimizedFactWireVector),
    ("signs the exact canonical minimized-fact payload", SignsCanonicalMinimizedFactPayload),
    ("rejects minimized-fact wire and continuity drift", RejectsMinimizedFactWireDrift),
    ("creates and validates exactly two local synthetic signed batches", ValidatesLocalSyntheticBatchProof),
    ("rejects local synthetic proof tampering and schema drift", RejectsLocalSyntheticBatchProofDrift),
    ("requires LocalService before creating a local synthetic proof", RejectsLocalSyntheticProofOutsideLocalService),
    ("opens the local proof with only native write-data authority", ValidatesLocalProofNativeFileAccess),
    ("creates and validates one genuine SCM metadata fact", ValidatesGenuineScmBatchProof),
    ("sends one exact Gate C0a loopback fact and accepts its receipt", ValidatesLoopbackFactTransport),
    ("rejects unsafe Gate C0a responses without retry", RejectsLoopbackFactTransportDrift),
    ("rejects unsafe Gate C0a input before network access", RejectsLoopbackFactTransportInput),
    ("freezes the Gate C0a handler and cancellation boundary", ValidatesLoopbackFactTransportBoundary),
    ("rebinds one genuine fact to the exact Gate C0c endpoint", ValidatesEndpointOneShotDelivery),
    ("rejects stale or weakened Gate C0c delivery state", RejectsEndpointOneShotDeliveryDrift),
    ("writes one delivery receipt and never retries", WritesEndpointDeliveryOnce),
    ("returns bounded no-match without fabricating a fact", ValidatesGenuineScmNoMatch),
    ("rejects genuine SCM metadata and time-window drift", RejectsGenuineScmMetadataDrift),
    ("salts the genuine source identity without cross-install linkability", ValidatesGenuineScmSourceHash),
    ("freezes the genuine SCM query boundary", ValidatesGenuineScmReaderBoundary),
    ("allows only the exact data receipt fields", AcceptsDataOnlyReceipt),
    ("exposes only the exact metadata-readiness plan and commands", ValidatesSourceReadinessPlan),
    ("freezes the non-mutating Security 4663 machine-readiness plan", ValidatesSecurity4663MachineReadinessPlan),
    ("rejects Security 4663 machine-readiness plan drift", RejectsSecurity4663MachineReadinessPlanDrift),
    ("checks Security 4663 readiness without reading events", ValidatesSecurity4663ReadinessCheck),
    ("fails Security 4663 readiness closed on prerequisite drift", RejectsSecurity4663ReadinessCheckDrift),
    ("freezes the reversible Security 4663 ceremony plan", ValidatesSecurity4663CeremonyPlan),
    ("applies the Security 4663 ceremony in exact order", ValidatesSecurity4663CeremonyApply),
    ("recovers original state when Security 4663 apply fails", ValidatesSecurity4663CeremonyRecovery),
    ("rolls Security 4663 readiness back in exact order", ValidatesSecurity4663CeremonyRollback),
    ("exercises Security 4663 readiness and restores original state", ValidatesSecurity4663CeremonyExercise),
    ("restores no-audit behavior with a settable native value", ValidatesSecurity4663AuditRestoreMapping),
    ("freezes the non-mutating Security 4663 one-shot plan", ValidatesSecurity4663OneShotPlan),
    ("rejects Security 4663 one-shot plan drift", RejectsSecurity4663OneShotPlanDrift),
    ("coordinates one fake bounded Security 4663 read", ValidatesSecurity4663OneShotCoordinator),
    ("returns bounded Security 4663 no-match without fabrication", ValidatesSecurity4663OneShotNoMatch),
    ("rejects Security 4663 one-shot prerequisite and result drift", RejectsSecurity4663OneShotCoordinatorDrift),
    ("freezes the Security 4663 one-shot query and XML boundary", ValidatesSecurity4663OneShotBoundedReader),
    ("maps bounded Security 4663 source failures without fabrication", ValidatesSecurity4663OneShotBoundedReaderFailures),
    ("rejects Security 4663 one-shot query and XML drift", RejectsSecurity4663OneShotBoundedReaderDrift),
    ("performs one exact disabled native Security 4663 source read", ValidatesNativeSecurity4663OneShotSource),
    ("returns native Security 4663 no-match and disposes", ValidatesNativeSecurity4663OneShotNoMatch),
    ("rejects native Security 4663 query drift before access", RejectsNativeSecurity4663OneShotSourceDrift),
    ("derives the Security 4663 baseline from metadata only", ValidatesSecurity4663OneShotBaseline),
    ("rejects invalid Security 4663 baseline metadata", RejectsSecurity4663OneShotBaselineDrift),
    ("selects only Security log metadata for the baseline", ValidatesNativeSecurity4663BaselineSource),
    ("freezes the Security 4663 LocalService operator ceremony", ValidatesSecurity4663OneShotOperatorPlan),
    ("rejects Security 4663 operator ceremony drift", RejectsSecurity4663OneShotOperatorPlanDrift),
    ("creates and consumes one signed Security 4663 approval", ValidatesSecurity4663OneShotApprovalLifecycle),
    ("rejects Security 4663 approval tampering and expiry", RejectsSecurity4663OneShotApprovalDrift),
    ("refuses Security 4663 approval overwrite and bad signing", RejectsSecurity4663OneShotApprovalOverwrite),
    ("creates and checks one signed normalized Security 4663 result", ValidatesSecurity4663OneShotResultLifecycle),
    ("binds a matched Security 4663 result without raw retention", ValidatesSecurity4663OneShotMatchResult),
    ("rejects Security 4663 result tampering and overwrite", RejectsSecurity4663OneShotResultDrift),
    ("freezes the protected Security 4663 result slot", ValidatesSecurity4663OneShotResultFileSlot),
    ("rejects Security 4663 result slot authority drift", RejectsSecurity4663OneShotResultFileSlotDrift),
    ("rejects stale and redirected Security 4663 result slots", RejectsSecurity4663OneShotResultNativeStateDrift),
    ("freezes the external Security 4663 result operator", ValidatesSecurity4663OneShotResultOperatorPlan),
    ("checks and consumes one externally validated Security 4663 result", ValidatesSecurity4663OneShotResultOperatorWorkflow),
    ("cleans the protected result slot without identity context", ValidatesSecurity4663OneShotResultIndependentCleanup),
    ("parses only an exact public P-256 machine identity blob", ValidatesDescriptorOnlyMachineIdentityBlob),
    ("freezes the protected Security 4663 approval file store", ValidatesSecurity4663OneShotApprovalFileStore),
    ("rejects Security 4663 approval file authority drift", RejectsSecurity4663OneShotApprovalFileStoreDrift),
    ("freezes the Security 4663 approval operator tool", ValidatesSecurity4663OneShotApprovalOperatorPlan),
    ("runs the pure no-event Security 4663 approval workflow", ValidatesSecurity4663OneShotApprovalOperatorWorkflow),
    ("freezes the LocalService Security 4663 consume-only proof", ValidatesSecurity4663ApprovalConsumeProofPlan),
    ("consumes one approval under LocalService without event access", ValidatesSecurity4663ApprovalConsumeProof),
    ("rejects consume-only proof drift before approval access", RejectsSecurity4663ApprovalConsumeProofDrift),
    ("creates and consumes one distinct live Security 4663 approval", ValidatesSecurity4663LiveOneShotApprovalLifecycle),
    ("rejects live Security 4663 readiness and authority drift", RejectsSecurity4663LiveOneShotApprovalContextDrift),
    ("rejects live Security 4663 tampering and approval-domain reuse", RejectsSecurity4663LiveOneShotApprovalDrift),
    ("freezes the protected live Security 4663 approval store", ValidatesSecurity4663LiveOneShotApprovalFileStore),
    ("rejects protected live approval ACL and native-state drift", RejectsSecurity4663LiveOneShotApprovalFileStoreDrift),
    ("freezes the elevated live Security 4663 approval operator", ValidatesSecurity4663LiveOneShotApprovalOperatorPlan),
    ("runs the pure live approval write-check-cleanup workflow", ValidatesSecurity4663LiveOneShotApprovalOperatorWorkflow),
    ("keeps live approval recovery independent and bounded", ValidatesSecurity4663LiveOneShotApprovalIndependentCleanup),
    ("creates and validates one distinct live normalized result", ValidatesSecurity4663LiveOneShotResultLifecycle),
    ("binds a live match without retaining raw identifiers", ValidatesSecurity4663LiveOneShotMatchResult),
    ("rejects live normalized result tampering and domain reuse", RejectsSecurity4663LiveOneShotResultDrift),
    ("freezes the protected live Security 4663 result slot", ValidatesSecurity4663LiveOneShotResultFileSlot),
    ("rejects protected live result slot authority drift", RejectsSecurity4663LiveOneShotResultFileSlotDrift),
    ("rejects stale and redirected live result slots", RejectsSecurity4663LiveOneShotResultNativeStateDrift),
    ("freezes the external live Security 4663 result operator", ValidatesSecurity4663LiveOneShotResultOperatorPlan),
    ("checks and consumes one external live Security 4663 result", ValidatesSecurity4663LiveOneShotResultOperatorWorkflow),
    ("freezes the exact live Security 4663 service boundary", ValidatesSecurity4663LiveOneShotExecutionPlan),
    ("freezes the pure C2g genuine-match boundary", ValidatesSecurity4663GenuineMatchValidationPlan),
    ("surfaces only a bounded C2f worker failure receipt", ValidatesSecurity4663LiveFailureReceipt),
    ("executes one approved live-shaped no-match workflow", ValidatesSecurity4663LiveOneShotExecution),
    ("rejects live execution drift before excess authority", RejectsSecurity4663LiveOneShotExecutionDrift),
    ("checks only System and Application log metadata", ChecksExactSourceMetadata),
    ("fails source readiness closed without reading events", RejectsUnavailableSourceMetadata),
    ("denies every alternate service startup argument", ValidatesServiceStartupArguments),
    ("proves Gate A only under the LocalService SID", ValidatesLocalServiceGateAReadiness),
    ("fails LocalService Gate A closed before an event read", RejectsLocalServiceGateAReadiness),
    ("keeps every inbound and action channel disabled", KeepsControlPlaneAbsent),
    ("freezes the bounded Gate C1a source contract", ValidatesBoundedCollectorContract),
    ("coordinates one bounded read per Gate C1a family", ValidatesBoundedCollectorCoordinator),
    ("fails Gate C1a closed on result drift", RejectsBoundedCollectorDrift),
    ("selects only the two frozen Gate C1b native queries", ValidatesNativeBoundedReaderSelection),
    ("creates and verifies one signed Gate C1c snapshot", ValidatesBoundedCollectorProof),
    ("rejects Gate C1c proof and freshness drift", RejectsBoundedCollectorProofDrift),
    ("writes the Gate C1c proof once without rereading", ValidatesBoundedCollectorProofWorker),
    ("normalizes one inert Security 1102 fixture without raw retention", ValidatesInertSecurity1102Parser),
    ("rejects Security 1102 metadata and field drift", RejectsInertSecurity1102ParserDrift),
    ("creates three fail-closed inert Security 4663 candidates", ValidatesInertSecurity4663Profiles),
    ("rejects Security 4663 metadata, field and access drift", RejectsInertSecurity4663ParserDrift),
    ("classifies inert Security 4663 inputs without raw retention", ValidatesInertSecurity4663LocalClassifier),
    ("rejects Security 4663 local-classification drift", RejectsInertSecurity4663LocalClassifierDrift)
};

var passed = 0;
foreach (var test in tests)
{
    try
    {
        test.Run();
        passed++;
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception error)
    {
        Console.Error.WriteLine($"FAIL {test.Name}: {error.Message}");
    }
}

Console.WriteLine($"Windows sensor boundary tests: {passed}/{tests.Length} passed.");
return passed == tests.Length ? 0 : 1;

static NativeKeyMetadata ValidKey() =>
    new(
        SensorBoundary.IdentityKeyName,
        SensorBoundary.SoftwareProviderName,
        CngAlgorithm.ECDsaP256.Algorithm,
        CngAlgorithmGroup.ECDsa.AlgorithmGroup,
        256,
        IsMachineKey: true,
        IsEphemeral: false,
        CngExportPolicies.None,
        CngKeyUsages.Signing);

static void AcceptsExactNativeKey()
{
    SensorIdentityPolicy.Validate(ValidKey());
}

static void RejectsKey(Func<NativeKeyMetadata, NativeKeyMetadata> mutate)
{
    try
    {
        SensorIdentityPolicy.Validate(mutate(ValidKey()));
    }
    catch (CryptographicException error) when (error.Message == "SENSOR_NATIVE_KEY_POLICY_INVALID")
    {
        return;
    }
    throw new InvalidOperationException("unsafe key metadata was accepted");
}

static void AcceptsExactProtectedAcl()
{
    var summary = NativeKeyAccessPolicy.Validate(
        NativeKeyAccessPolicy.CreateProtectedDescriptor());
    if (
        summary.OwnerSid != NativeKeyAccessPolicy.BuiltinAdministratorsSid ||
        summary.GroupSid != NativeKeyAccessPolicy.BuiltinAdministratorsSid ||
        !summary.DaclProtected ||
        summary.AllowedPrincipalCount != 3 ||
        summary.ServiceSid != NativeKeyAccessPolicy.LocalServiceSid ||
        summary.ServiceAccess != "generic-read-only")
    {
        throw new InvalidOperationException("protected ACL summary was not exact");
    }
}

static void AcceptsSoftwareKspNormalizedAcl()
{
    NativeKeyAccessPolicy.Validate(ToDescriptor(
        "O:BAG:BAD:P" +
        "(A;;0xd01f01ff;;;SY)" +
        "(A;;0xd01f01ff;;;BA)" +
        "(A;;0x80120089;;;LS)"));
}

static void RejectsAcl(string sddl)
{
    try
    {
        NativeKeyAccessPolicy.Validate(ToDescriptor(sddl));
    }
    catch (CryptographicException error) when (error.Message == "SENSOR_NATIVE_KEY_ACL_INVALID")
    {
        return;
    }
    throw new InvalidOperationException("unsafe native-key ACL was accepted");
}

static void ValidatesServiceSidHardeningPlan()
{
    var plan = ServiceSidHardeningCheckpoint.BuildSourceOnlyPlan();
    ServiceSidHardeningCheckpoint.Validate(plan);
    if (
        plan.ScmLogonAccount != @"NT AUTHORITY\LocalService" ||
        plan.ResourceAuthorityAccount != @"NT SERVICE\WARRoomWindowsSensor" ||
        plan.ExistingKeyName != SensorBoundary.IdentityKeyName ||
        plan.ReplacementKeyName != "WAR-R00M.WindowsSensor.Identity.v2" ||
        plan.OrderedSteps.Count != 9 ||
        plan.OrderedSteps[1] != "enable-and-read-back-unrestricted-service-sid" ||
        plan.OrderedSteps[2] != "resolve-fixed-service-account-through-windows" ||
        plan.OrderedSteps[3] != "create-non-exportable-v2-key-with-service-sid-read-only" ||
        plan.PerformsMachineMutation ||
        plan.TelemetryEnabled || plan.TransportEnabled || plan.CommandChannelEnabled)
    {
        throw new InvalidOperationException("service SID source checkpoint drifted");
    }
}

static void ValidatesServiceSidAuthority()
{
    const string sid = "S-1-5-80-111111111-222222222-333333333-444444444-555555555";
    var resolved = ServiceSidAuthority.ResolveAndValidate(new FakeServiceSidAuthority(
        new ServiceSidNativeSnapshot(
            SensorBoundary.ServiceName,
            SensorBoundary.ExpectedServiceIdentity,
            ServiceSidAuthority.AccountName,
            ServiceSidAuthority.DomainName,
            sid,
            ServiceSidAuthority.Unrestricted)));
    if (
        resolved.ServiceName != SensorBoundary.ServiceName ||
        resolved.AccountName != ServiceSidAuthority.AccountName ||
        resolved.Sid != sid)
    {
        throw new InvalidOperationException("fixed service SID was not preserved");
    }
}

static void ValidatesServiceSidKeyAcl()
{
    var serviceSid = new ResolvedServiceSid(
        SensorBoundary.ServiceName,
        ServiceSidAuthority.AccountName,
        "S-1-5-80-111111111-222222222-333333333-444444444-555555555");
    var summary = NativeKeyAccessPolicy.ValidateServiceSidProtectedDescriptor(
        NativeKeyAccessPolicy.CreateServiceSidProtectedDescriptor(serviceSid),
        serviceSid);
    if (
        summary.ServiceSid != serviceSid.Sid ||
        summary.ServiceAccess != "service-sid-read-only" ||
        summary.AllowedPrincipalCount != 3)
    {
        throw new InvalidOperationException("service SID key ACL was not exact");
    }

    RejectsServiceSidKeyAcl(
        NativeKeyAccessPolicy.ProtectedDescriptorSddl,
        serviceSid);
    RejectsServiceSidKeyAcl(
        $"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GW;;;{serviceSid.Sid})",
        serviceSid);
    RejectsServiceSidKeyAcl(
        $"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;{serviceSid.Sid})(A;;GR;;;LS)",
        serviceSid);
}

static void RejectsServiceSidKeyAcl(string sddl, ResolvedServiceSid serviceSid)
{
    try
    {
        NativeKeyAccessPolicy.ValidateServiceSidProtectedDescriptor(
            ToDescriptor(sddl),
            serviceSid);
    }
    catch (CryptographicException error) when (
        error.Message == "SENSOR_NATIVE_KEY_ACL_INVALID")
    {
        return;
    }
    throw new InvalidOperationException("unsafe service SID key ACL was accepted");
}

static void RejectsServiceSidHardeningDrift()
{
    var plan = ServiceSidHardeningCheckpoint.BuildSourceOnlyPlan();
    RejectServiceSidPlan(plan with { AcceptsCallerSuppliedSid = true });
    RejectServiceSidPlan(plan with { GrantsGenericLocalServiceResourceAccess = true });
    RejectServiceSidPlan(plan with { ConfiguresSidBeforeResourceAcls = false });
    RejectServiceSidPlan(plan with { PermitsLegacyAclRollback = true });
    RejectServiceSidPlan(plan with { PerformsMachineMutation = true });
    RejectServiceSidPlan(plan with { TelemetryEnabled = true });
    RejectServiceSidPlan(plan with
    {
        OrderedSteps = plan.OrderedSteps.Reverse().ToArray()
    });

    RejectServiceSidAuthority(new ServiceSidNativeSnapshot(
        SensorBoundary.ServiceName,
        SensorBoundary.ExpectedServiceIdentity,
        ServiceSidAuthority.AccountName,
        ServiceSidAuthority.DomainName,
        NativeKeyAccessPolicy.LocalServiceSid,
        ServiceSidAuthority.Unrestricted));
    RejectServiceSidAuthority(new ServiceSidNativeSnapshot(
        "OtherService",
        SensorBoundary.ExpectedServiceIdentity,
        ServiceSidAuthority.AccountName,
        ServiceSidAuthority.DomainName,
        "S-1-5-80-1-2-3-4-5",
        ServiceSidAuthority.Unrestricted));
    RejectServiceSidAuthority(new ServiceSidNativeSnapshot(
        SensorBoundary.ServiceName,
        SensorBoundary.ExpectedServiceIdentity,
        ServiceSidAuthority.AccountName,
        ServiceSidAuthority.DomainName,
        "S-1-5-80-1-2-3-4-5",
        0));
    RejectServiceSidAuthority(new ServiceSidNativeSnapshot(
        SensorBoundary.ServiceName,
        @"LocalSystem",
        ServiceSidAuthority.AccountName,
        ServiceSidAuthority.DomainName,
        "S-1-5-80-1-2-3-4-5",
        ServiceSidAuthority.Unrestricted));
}

static void AppliesUnrestrictedServiceSid()
{
    var native = FakeServiceSidConfigurationNative.Create(
        ServiceSidConfigurator.None);
    var result = ServiceSidConfigurator.ApplyUnrestricted(native);
    if (
        result.PreviousSidType != ServiceSidConfigurator.None ||
        result.CurrentSidType != ServiceSidAuthority.Unrestricted ||
        !result.Changed ||
        native.SetCalls != 1 ||
        native.ReadCalls != 2)
    {
        throw new InvalidOperationException(
            "service SID apply result drifted");
    }
}

static void KeepsUnrestrictedServiceSid()
{
    var native = FakeServiceSidConfigurationNative.Create(
        ServiceSidAuthority.Unrestricted);
    var result = ServiceSidConfigurator.ApplyUnrestricted(native);
    if (result.Changed || native.SetCalls != 0 || native.ReadCalls != 1)
    {
        throw new InvalidOperationException(
            "service SID idempotence drifted");
    }
}

static void RecoversServiceSidAfterApplyDrift()
{
    var native = FakeServiceSidConfigurationNative.Create(
        ServiceSidConfigurator.Restricted);
    native.IgnoreSetNumber = 1;
    try
    {
        _ = ServiceSidConfigurator.ApplyUnrestricted(native);
    }
    catch (InvalidOperationException error) when (
        error.Message == "SENSOR_SERVICE_SID_APPLY_FAILED")
    {
        if (
            native.CurrentSidType != ServiceSidConfigurator.Restricted ||
            native.SetCalls != 2 ||
            native.ReadCalls != 3)
        {
            throw new InvalidOperationException(
                "service SID apply recovery drifted");
        }
        return;
    }

    throw new InvalidOperationException(
        "service SID apply drift was accepted");
}

static void RestoresPreviousServiceSidType()
{
    var native = FakeServiceSidConfigurationNative.Create(
        ServiceSidAuthority.Unrestricted);
    var result = ServiceSidConfigurator.RestorePrevious(
        native,
        ServiceSidConfigurator.Restricted);
    if (
        result.PreviousSidType != ServiceSidAuthority.Unrestricted ||
        result.CurrentSidType != ServiceSidConfigurator.Restricted ||
        !result.Changed ||
        native.SetCalls != 1 ||
        native.ReadCalls != 2)
    {
        throw new InvalidOperationException(
            "service SID rollback result drifted");
    }
}

static void RejectsServiceSidConfigurationDrift()
{
    foreach (var invalidType in new uint[] { 2, 4, uint.MaxValue })
    {
        try
        {
            ServiceSidConfigurator.ValidateSidType(invalidType);
        }
        catch (InvalidOperationException error) when (
            error.Message == "SENSOR_SERVICE_SID_TYPE_INVALID")
        {
            continue;
        }
        throw new InvalidOperationException(
            "invalid service SID type was accepted");
    }

    var wrongService = FakeServiceSidConfigurationNative.Create(
        ServiceSidConfigurator.None) with
    {
        ServiceName = "OtherService"
    };
    try
    {
        _ = ServiceSidConfigurator.ApplyUnrestricted(wrongService);
    }
    catch (InvalidOperationException error) when (
        error.Message ==
        "SENSOR_SERVICE_SID_CONFIGURATION_AUTHORITY_INVALID")
    {
        if (wrongService.SetCalls == 0) return;
    }

    throw new InvalidOperationException(
        "invalid service SID configuration authority was accepted");
}

static void ValidatesServiceSidStatusAuthority()
{
    var valid = FakeServiceSidConfigurationNative.Create(
        ServiceSidAuthority.Unrestricted);
    var snapshot = ServiceSidConfigurator.ReadValidated(valid);
    if (
        snapshot.ServiceSidType != ServiceSidAuthority.Unrestricted ||
        valid.ReadCalls != 1)
    {
        throw new InvalidOperationException(
            "service SID status validation result drifted");
    }

    var wrongIdentity = FakeServiceSidConfigurationNative.Create(
        ServiceSidAuthority.Unrestricted) with
    {
        ScmLogonAccount = "LocalSystem"
    };
    try
    {
        _ = ServiceSidConfigurator.ReadValidated(wrongIdentity);
    }
    catch (InvalidOperationException error) when (
        error.Message ==
        "SENSOR_SERVICE_SID_CONFIGURATION_AUTHORITY_INVALID")
    {
        return;
    }

    throw new InvalidOperationException(
        "service SID status accepted a false service identity");
}

static void ValidatesServiceSidToolCommands()
{
    var expected = new Dictionary<string, ServiceSidToolCommand>(
        StringComparer.Ordinal)
    {
        ["plan"] = ServiceSidToolCommand.Plan,
        ["status"] = ServiceSidToolCommand.Status,
        ["apply-unrestricted"] = ServiceSidToolCommand.ApplyUnrestricted,
        ["restore-none"] = ServiceSidToolCommand.RestoreNone,
        ["restore-restricted"] = ServiceSidToolCommand.RestoreRestricted
    };
    foreach (var item in expected)
    {
        if (ServiceSidToolCommandParser.Parse([item.Key]) != item.Value)
        {
            throw new InvalidOperationException(
                "service SID tool command drifted");
        }
    }

    foreach (var rejected in new[]
    {
        "set", "restore", "WARRoomWindowsSensor", "2", "--service"
    })
    {
        try
        {
            _ = ServiceSidToolCommandParser.Parse([rejected]);
        }
        catch (InvalidDataException error) when (
            error.Message == "SENSOR_SERVICE_SID_COMMAND_INVALID")
        {
            continue;
        }
        throw new InvalidOperationException(
            "unsafe service SID tool command was accepted");
    }
}

static void RejectServiceSidPlan(ServiceSidHardeningPlan plan)
{
    try
    {
        ServiceSidHardeningCheckpoint.Validate(plan);
    }
    catch (InvalidOperationException error) when (
        error.Message == "SENSOR_SERVICE_SID_PLAN_INVALID")
    {
        return;
    }
    throw new InvalidOperationException("unsafe service SID plan was accepted");
}

static void RejectServiceSidAuthority(ServiceSidNativeSnapshot snapshot)
{
    try
    {
        ServiceSidAuthority.ResolveAndValidate(new FakeServiceSidAuthority(snapshot));
    }
    catch (InvalidOperationException error) when (
        error.Message == "SENSOR_SERVICE_SID_AUTHORITY_INVALID")
    {
        return;
    }
    throw new InvalidOperationException("unsafe service SID authority was accepted");
}

static byte[] ToDescriptor(string sddl)
{
    var descriptor = new RawSecurityDescriptor(sddl);
    var binary = new byte[descriptor.BinaryLength];
    descriptor.GetBinaryForm(binary, 0);
    return binary;
}

static void ValidatesProvisioningPlan()
{
    var plan = NativeIdentityProvisioner.BuildPlan();
    if (
        plan.Profile != SensorBoundary.NativeIdentityProfile ||
        plan.Provider != SensorBoundary.SoftwareProviderName ||
        plan.ServiceIdentity != SensorBoundary.ExpectedServiceIdentity ||
        plan.ServiceAccess != "generic-read-only" ||
        !plan.RequiresElevation ||
        plan.ReplacesExistingIdentity ||
        plan.PermitsCommandChannel)
    {
        throw new InvalidOperationException("provisioning plan exceeded the identity boundary");
    }
}

static void ValidatesProvisionerCommands()
{
    if (
        NativeIdentityProvisionerCommandParser.Parse(["plan"]) != NativeIdentityProvisionerCommand.Plan ||
        NativeIdentityProvisionerCommandParser.Parse(["status"]) != NativeIdentityProvisionerCommand.Status ||
        NativeIdentityProvisionerCommandParser.Parse(["provision"]) != NativeIdentityProvisionerCommand.Provision ||
        NativeIdentityProvisionerCommandParser.Parse(["enrollment-identity"]) != NativeIdentityProvisionerCommand.EnrollmentIdentity ||
        NativeIdentityProvisionerCommandParser.Parse(["sign-enrollment-challenge"]) != NativeIdentityProvisionerCommand.SignEnrollmentChallenge ||
        NativeIdentityProvisionerCommandParser.Parse(["probe-plan"]) != NativeIdentityProvisionerCommand.ProbePlan ||
        NativeIdentityProvisionerCommandParser.Parse(["probe-status"]) != NativeIdentityProvisionerCommand.ProbeStatus ||
        NativeIdentityProvisionerCommandParser.Parse(["probe-cleanup"]) != NativeIdentityProvisionerCommand.ProbeCleanup)
    {
        throw new InvalidOperationException("a supported provisioner command parsed incorrectly");
    }

    foreach (var rejected in new[] { "remove", "repair", "replace", "export", "shell", "delete-key" })
    {
        try
        {
            NativeIdentityProvisionerCommandParser.Parse([rejected]);
        }
        catch (InvalidDataException error) when (error.Message == "SENSOR_PROVISIONER_COMMAND_INVALID")
        {
            continue;
        }
        throw new InvalidOperationException($"unsafe command was accepted: {rejected}");
    }
}

static (string Candidate, DateTime Now) EndpointBindingFixture(
    ISensorIdentitySigner identity)
{
    var now = new DateTime(2026, 8, 3, 12, 0, 0, DateTimeKind.Utc);
    var candidate = JsonSerializer.Serialize(new
    {
        schemaVersion = 1,
        profile = EndpointBindingLifecycle.CandidateProfile,
        state = "capability-pending",
        missionId = "11111111-1111-4111-8111-111111111111",
        connectorId = "connector-22222222-2222-4222-8222-222222222222",
        endpointId = "endpoint-33333333-3333-4333-8333-333333333333",
        enrollmentChallengeId = "enrollment-44444444-4444-4444-8444-444444444444",
        certificateFingerprintSha256 = identity.Descriptor.CertificateFingerprintSha256,
        identityIssuedAt = "2026-08-03T11:55:00.000Z",
        identityExpiresAt = "2026-08-09T11:55:00.000Z",
        provider = EndpointBindingLifecycle.Provider,
        channel = EndpointBindingLifecycle.Channel,
        eventFamily = EndpointBindingLifecycle.EventFamily,
        fields = EndpointBindingLifecycle.Fields,
        filterHash = EndpointBindingLifecycle.FilterHash,
        collectorVersion = EndpointBindingLifecycle.CollectorVersion
    });
    return (candidate, now);
}

static void ValidatesPendingEndpointBinding()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = EndpointBindingFixture(identity);
    var pending = EndpointBindingLifecycle.CreatePending(
        fixture.Candidate, identity.Descriptor, new string('a', 40), fixture.Now);
    var roundTrip = EndpointBindingLifecycle.ValidatePending(
        EndpointBindingLifecycle.SerializePending(pending), identity.Descriptor,
        new string('a', 40), fixture.Now);
    if (
        roundTrip.State != "coverage-blocked" || roundTrip.CollectorEnabled ||
        roundTrip.TelemetryEnabled || roundTrip.CommandChannelEnabled ||
        roundTrip.ServiceSourceCommit != new string('a', 40))
    {
        throw new InvalidOperationException("pending binding exceeded its authority");
    }
}

static void ValidatesEndpointCapabilityProof()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = EndpointBindingFixture(identity);
    var pending = EndpointBindingLifecycle.CreatePending(
        fixture.Candidate, identity.Descriptor, new string('a', 40), fixture.Now);
    var reader = new FakeGenuineScmEventReader(new GenuineScmEventMetadata(
        NativeGenuineScmEventReader.ProviderName,
        NativeGenuineScmEventReader.EventId,
        NativeGenuineScmEventReader.Level,
        new DateTimeOffset(fixture.Now.AddMinutes(-1)), 42));
    var proof = EndpointBindingLifecycle.CreateCapabilityProof(
        pending, identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        reader, fixture.Now);
    var validated = EndpointBindingLifecycle.ValidateCapabilityProof(
        EndpointBindingLifecycle.SerializeCapabilityProof(proof), pending,
        identity.Descriptor, fixture.Now.AddSeconds(1));
    if (
        validated.Loss.State != "unknown" || validated.Loss.LostRecordCount is not null ||
        validated.Continuity != "unknown" || reader.ReadCount != 1)
    {
        throw new InvalidOperationException("one-shot capability overstated continuity");
    }
}

static void RejectsEndpointCapabilityDrift()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = EndpointBindingFixture(identity);
    var pending = EndpointBindingLifecycle.CreatePending(
        fixture.Candidate, identity.Descriptor, new string('a', 40), fixture.Now);
    var proof = EndpointBindingLifecycle.CreateCapabilityProof(
        pending, identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        new FakeGenuineScmEventReader(new GenuineScmEventMetadata(
            NativeGenuineScmEventReader.ProviderName,
            NativeGenuineScmEventReader.EventId,
            NativeGenuineScmEventReader.Level,
            new DateTimeOffset(fixture.Now), 7)),
        fixture.Now);
    var drifted = EndpointBindingLifecycle.SerializeCapabilityProof(
        proof with { Continuity = "continuous" });
    try
    {
        EndpointBindingLifecycle.ValidateCapabilityProof(
            drifted, pending, identity.Descriptor, fixture.Now.AddSeconds(1));
    }
    catch (InvalidDataException error) when (
        error.Message == "SENSOR_CAPABILITY_PROOF_INVALID")
    {
        return;
    }
    throw new InvalidOperationException("capability drift was accepted");
}

static (PendingEndpointBinding Pending, SignedEndpointCapabilityProof Proof, string FinalInput)
    FinalBindingFixture(ISensorIdentitySigner identity)
{
    var fixture = EndpointBindingFixture(identity);
    var pending = EndpointBindingLifecycle.CreatePending(
        fixture.Candidate, identity.Descriptor, new string('a', 40), fixture.Now);
    var proof = EndpointBindingLifecycle.CreateCapabilityProof(
        pending, identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        new FakeGenuineScmEventReader(new GenuineScmEventMetadata(
            NativeGenuineScmEventReader.ProviderName,
            NativeGenuineScmEventReader.EventId,
            NativeGenuineScmEventReader.Level,
            new DateTimeOffset(fixture.Now), 9)),
        fixture.Now);
    var finalInput = JsonSerializer.Serialize(new
    {
        schemaVersion = 1,
        profile = EndpointBindingLifecycle.FinalInputProfile,
        state = "coverage-blocked",
        missionId = pending.MissionId,
        connectorId = pending.ConnectorId,
        endpointId = pending.EndpointId,
        enrollmentChallengeId = pending.EnrollmentChallengeId,
        certificateFingerprintSha256 = pending.CertificateFingerprintSha256,
        identityIssuedAt = pending.IdentityIssuedAt,
        identityExpiresAt = pending.IdentityExpiresAt,
        provider = pending.Provider,
        channel = pending.Channel,
        eventFamily = pending.EventFamily,
        fields = pending.Fields,
        filterHash = pending.FilterHash,
        collectorVersion = pending.CollectorVersion,
        capabilitySnapshotId = "capability-55555555-5555-4555-8555-555555555555",
        capabilityReportHash = proof.ReportHash,
        capabilityFreshUntil = "2026-08-03T12:05:00.000Z"
    });
    return (pending, proof, finalInput);
}

static void FinalizesEndpointBinding()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = FinalBindingFixture(identity);
    var final = EndpointBindingLifecycle.FinalizeBinding(
        fixture.FinalInput, fixture.Pending, fixture.Proof, identity.Descriptor,
        new string('a', 40), new DateTime(2026, 8, 3, 12, 1, 0, DateTimeKind.Utc));
    var validated = EndpointBindingLifecycle.ValidateFinal(
        EndpointBindingLifecycle.SerializeFinal(final),
        EndpointBindingLifecycle.SerializeCapabilityProof(fixture.Proof),
        identity.Descriptor, new string('a', 40),
        new DateTime(2026, 8, 3, 12, 10, 0, DateTimeKind.Utc));
    if (validated.State != "coverage-blocked" || validated.CollectorEnabled ||
        validated.TelemetryEnabled || validated.CommandChannelEnabled ||
        validated.CapabilityReportHash != fixture.Proof.ReportHash)
        throw new InvalidOperationException("final binding exceeded its blocked authority");
}

static void RejectsEndpointBindingDrift()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = FinalBindingFixture(identity);
    ExpectInvalidData(
        () => EndpointBindingLifecycle.FinalizeBinding(
            fixture.FinalInput.Replace(fixture.Proof.ReportHash, new string('b', 64)),
            fixture.Pending, fixture.Proof, identity.Descriptor, new string('a', 40),
            new DateTime(2026, 8, 3, 12, 1, 0, DateTimeKind.Utc)),
        "SENSOR_FINAL_BINDING_CAPABILITY_INVALID");
    ExpectInvalidData(
        () => EndpointBindingLifecycle.CreatePending(
            fixture.FinalInput.Replace(
                EndpointBindingLifecycle.FinalInputProfile,
                EndpointBindingLifecycle.CandidateProfile),
            identity.Descriptor, new string('a', 40),
            new DateTime(2026, 8, 3, 12, 1, 0, DateTimeKind.Utc)),
        "SENSOR_BINDING_CANDIDATE_FIELDS_INVALID");
}

static void WritesCapabilityProofOnce()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = EndpointBindingFixture(identity);
    var pending = EndpointBindingLifecycle.CreatePending(
        fixture.Candidate, identity.Descriptor, new string('a', 40), fixture.Now);
    var store = new FakeEndpointBindingStore
    {
        Binding = EndpointBindingLifecycle.SerializePending(pending)
    };
    var reader = new FakeGenuineScmEventReader(new GenuineScmEventMetadata(
        NativeGenuineScmEventReader.ProviderName,
        NativeGenuineScmEventReader.EventId,
        NativeGenuineScmEventReader.Level,
        new DateTimeOffset(fixture.Now), 10));
    var worker = new EndpointCapabilityProofWorker(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        reader,
        store,
        new FakeInstallManifestBindingReader(new(
            new string('a', 40), identity.Descriptor.CertificateFingerprintSha256,
            new string('0', 64))),
        new FixedTestTimeProvider(fixture.Now),
        NullLogger<EndpointCapabilityProofWorker>.Instance);
    worker.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
    worker.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
    if (reader.ReadCount != 1 || store.WriteCount != 1 || store.CapabilityProof is null)
        throw new InvalidOperationException("capability proof was not one-shot");
}

static (string Json, string CanonicalPayload, string ChallengeHash)
    EnrollmentChallengeFixture(ISensorIdentitySigner identity)
{
    const string challengeId =
        "enrollment-11111111-1111-4111-8111-111111111111";
    const string missionId = "22222222-2222-4222-8222-222222222222";
    const string connectorId =
        "connector-33333333-3333-4333-8333-333333333333";
    const string endpointId =
        "endpoint-44444444-4444-4444-8444-444444444444";
    const string nonce = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
    const string requestedAt = "2026-08-03T09:00:00.000Z";
    const string challengeExpiresAt = "2026-08-03T09:05:00.000Z";
    const string identityExpiresAt = "2026-08-10T09:00:00.000Z";
    var canonicalPayload =
        "{\"certificateFingerprintSha256\":\"" +
        identity.Descriptor.CertificateFingerprintSha256 +
        "\",\"challengeExpiresAt\":\"" + challengeExpiresAt +
        "\",\"challengeId\":\"" + challengeId +
        "\",\"connectorId\":\"" + connectorId +
        "\",\"endpointId\":\"" + endpointId +
        "\",\"identityExpiresAt\":\"" + identityExpiresAt +
        "\",\"missionId\":\"" + missionId +
        "\",\"nonceBase64Url\":\"" + nonce +
        "\",\"requestedAt\":\"" + requestedAt +
        "\",\"schemaVersion\":1}";
    var challengeHash = Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(canonicalPayload)))
        .ToLowerInvariant();
    var json = JsonSerializer.Serialize(new
    {
        challenge = new
        {
            id = challengeId,
            status = "pending",
            payload = new
            {
                schemaVersion = 1,
                challengeId,
                missionId,
                connectorId,
                endpointId,
                certificateFingerprintSha256 =
                    identity.Descriptor.CertificateFingerprintSha256,
                nonceBase64Url = nonce,
                requestedAt,
                challengeExpiresAt,
                identityExpiresAt
            },
            challengeHash
        }
    });
    return (json, canonicalPayload, challengeHash);
}

static void SignsExactEnrollmentChallenge()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = EnrollmentChallengeFixture(identity);
    var proof = NativeEnrollmentChallenge.Sign(
        fixture.Json,
        identity,
        new DateTime(2026, 8, 3, 9, 1, 0, DateTimeKind.Utc));
    if (
        proof.SchemaVersion != 1 ||
        proof.ChallengeId != "enrollment-11111111-1111-4111-8111-111111111111" ||
        proof.ChallengeHash != fixture.ChallengeHash ||
        proof.CertificateFingerprintSha256 !=
            identity.Descriptor.CertificateFingerprintSha256 ||
        proof.PublicKeySpkiBase64 != identity.Descriptor.PublicKeySpkiBase64 ||
        proof.CanonicalPayload != fixture.CanonicalPayload ||
        Convert.FromBase64String(proof.ProofSignatureBase64).Length != 64 ||
        proof.ChallengeExpiresAt != "2026-08-03T09:05:00.000Z" ||
        proof.IdentityExpiresAt != "2026-08-10T09:00:00.000Z")
    {
        throw new InvalidOperationException("enrollment proof was not exact");
    }
}

static void RejectsEnrollmentChallengeDrift()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = EnrollmentChallengeFixture(identity);
    var now = new DateTime(2026, 8, 3, 9, 1, 0, DateTimeKind.Utc);
    var cases = new (string Json, string Error)[]
    {
        (fixture.Json.Replace(
            "\"challenge\":",
            "\"command\":\"whoami\",\"challenge\":",
            StringComparison.Ordinal),
            "SENSOR_ENROLLMENT_CHALLENGE_FIELDS_INVALID"),
        (fixture.Json.Replace(
            "\"status\":\"pending\"",
            "\"status\":\"approved\"",
            StringComparison.Ordinal),
            "SENSOR_ENROLLMENT_CHALLENGE_VALUE_INVALID"),
        (fixture.Json.Replace(
            identity.Descriptor.CertificateFingerprintSha256,
            new string('a', 64),
            StringComparison.Ordinal),
            "SENSOR_ENROLLMENT_CHALLENGE_VALUE_INVALID"),
        (fixture.Json.Replace(
            fixture.ChallengeHash,
            new string('b', 64),
            StringComparison.Ordinal),
            "SENSOR_ENROLLMENT_CHALLENGE_HASH_INVALID"),
        (fixture.Json.Replace(
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB",
            StringComparison.Ordinal),
            "SENSOR_ENROLLMENT_CHALLENGE_VALUE_INVALID")
    };
    foreach (var item in cases)
    {
        ExpectInvalidData(
            () => NativeEnrollmentChallenge.Sign(item.Json, identity, now),
            item.Error);
    }
    ExpectInvalidData(
        () => NativeEnrollmentChallenge.Sign(
            fixture.Json,
            identity,
            new DateTime(2026, 8, 3, 9, 5, 0, DateTimeKind.Utc)),
        "SENSOR_ENROLLMENT_CHALLENGE_TIME_INVALID");
    ExpectInvalidData(
        () => NativeEnrollmentChallenge.Sign("{\"payload\":\"calc.exe\"}", identity, now),
        "SENSOR_ENROLLMENT_CHALLENGE_FIELDS_INVALID");
    ExpectInvalidData(
        () => NativeEnrollmentChallenge.Sign(
            new string('x', NativeEnrollmentChallenge.MaximumInputBytes + 1),
            identity,
            now),
        "SENSOR_ENROLLMENT_CHALLENGE_INPUT_INVALID");
}

static void RejectsCorruptEnrollmentProof()
{
    using var identity = new FakeSensorIdentitySigner { CorruptSignature = true };
    var fixture = EnrollmentChallengeFixture(identity);
    ExpectInvalidData(
        () => NativeEnrollmentChallenge.Sign(
            fixture.Json,
            identity,
            new DateTime(2026, 8, 3, 9, 1, 0, DateTimeKind.Utc)),
        "SENSOR_ENROLLMENT_CHALLENGE_PROOF_INVALID");
}

static NativeKeyMetadata ValidDiagnosticProbe() =>
    new(
        DiagnosticProbeCleanup.ProbeName,
        SensorBoundary.SoftwareProviderName,
        CngAlgorithm.ECDsaP256.Algorithm,
        CngAlgorithmGroup.ECDsa.AlgorithmGroup,
        256,
        IsMachineKey: false,
        IsEphemeral: false,
        CngExportPolicies.None,
        CngKeyUsages.Signing);

static void ValidatesDiagnosticProbePlan()
{
    var plan = DiagnosticProbeCleanup.BuildPlan();
    if (
        plan.ProbeName != DiagnosticProbeCleanup.ProbeName ||
        plan.ProbeName == SensorBoundary.IdentityKeyName ||
        !plan.RequiresElevation ||
        !plan.RemovesOnlyExactProbe ||
        plan.DeletesProductionMachineIdentity)
    {
        throw new InvalidOperationException(
            "diagnostic probe plan exceeded its exact cleanup boundary");
    }
}

static void ReadsDiagnosticProbeStatus()
{
    var store = new FakeDiagnosticProbeStore
    {
        KeyExists = true
    };
    var status = DiagnosticProbeCleanup.ReadStatus(store);
    if (
        !status.Exists ||
        !status.PolicyValid ||
        store.OpenCount != 1 ||
        store.Key.DeleteCount != 0)
    {
        throw new InvalidOperationException(
            "diagnostic probe status mutated the key");
    }
}

static void CleansMissingDiagnosticProbe()
{
    var store = new FakeDiagnosticProbeStore();
    var result = DiagnosticProbeCleanup.Cleanup(store);
    if (
        result.Removed ||
        !result.AlreadyAbsent ||
        !result.ProductionMachineIdentityPreserved ||
        store.OpenCount != 0 ||
        store.Key.DeleteCount != 0)
    {
        throw new InvalidOperationException(
            "missing diagnostic probe cleanup was not idempotent");
    }
}

static void CleansExactDiagnosticProbe()
{
    var store = new FakeDiagnosticProbeStore
    {
        KeyExists = true
    };
    var result = DiagnosticProbeCleanup.Cleanup(store);
    if (
        !result.Removed ||
        result.AlreadyAbsent ||
        !result.ProductionMachineIdentityPreserved ||
        store.KeyExists ||
        store.OpenCount != 1 ||
        store.Key.DeleteCount != 1)
    {
        throw new InvalidOperationException(
            "exact diagnostic probe cleanup was not bounded");
    }
}

static void RejectsDiagnosticProbeDrift()
{
    var drifts =
        new (string Name, Func<NativeKeyMetadata, NativeKeyMetadata> Mutate)[]
        {
            (
                "production identity name",
                key => key with { KeyName = SensorBoundary.IdentityKeyName }
            ),
            (
                "unexpected probe name",
                key => key with { KeyName = "WAR-R00M-Acl-Probe-Unreviewed" }
            ),
            (
                "provider",
                key => key with { ProviderName = "Unexpected Provider" }
            ),
            (
                "algorithm",
                key => key with { Algorithm = CngAlgorithm.Rsa.Algorithm }
            ),
            (
                "algorithm group",
                key => key with
                {
                    AlgorithmGroup = CngAlgorithmGroup.Rsa.AlgorithmGroup
                }
            ),
            ("key size", key => key with { KeySize = 384 }),
            ("machine scope", key => key with { IsMachineKey = true }),
            ("ephemeral state", key => key with { IsEphemeral = true }),
            (
                "export policy",
                key => key with
                {
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport
                }
            ),
            (
                "key usage",
                key => key with { KeyUsage = CngKeyUsages.Decryption }
            )
        };

    foreach (var drift in drifts)
    {
        var store = new FakeDiagnosticProbeStore
        {
            KeyExists = true
        };
        store.Key.Metadata = drift.Mutate(ValidDiagnosticProbe());
        try
        {
            DiagnosticProbeCleanup.Cleanup(store);
        }
        catch (CryptographicException error) when (
            error.Message == "SENSOR_DIAGNOSTIC_PROBE_POLICY_INVALID")
        {
            if (store.Key.DeleteCount != 0 || !store.KeyExists)
            {
                throw new InvalidOperationException(
                    $"drifted diagnostic probe was mutated: {drift.Name}");
            }
            continue;
        }
        throw new InvalidOperationException(
            $"diagnostic probe metadata drift was accepted: {drift.Name}");
    }
}

static void ReadsMissingStatusWithoutOpening()
{
    var store = new FakeKeyStore { KeyExists = false };
    var status = NativeIdentityProvisioner.ReadStatus(store);
    if (
        status.Exists ||
        status.PolicyValid ||
        store.OpenCount != 0 ||
        store.CreateCount != 0)
    {
        throw new InvalidOperationException("missing-key status mutated or opened the key store");
    }
}

static void ReadsValidStatusWithoutDeleting()
{
    var store = new FakeKeyStore { KeyExists = true };
    var status = NativeIdentityProvisioner.ReadStatus(store);
    if (
        !status.Exists ||
        !status.PolicyValid ||
        status.AclVerified != true ||
        string.IsNullOrWhiteSpace(status.PublicKeyFingerprintSha256) ||
        store.OpenCount != 1 ||
        store.CreateCount != 0 ||
        store.Identity.DeleteCount != 0)
    {
        throw new InvalidOperationException("valid status did not remain read-only");
    }
}

static void RejectsExportableStatusWithoutDeleting()
{
    var store = new FakeKeyStore { KeyExists = true };
    store.Identity.PrivateExportBlocked = false;
    var status = NativeIdentityProvisioner.ReadStatus(store);
    if (
        !status.Exists ||
        status.PolicyValid ||
        status.ErrorCode != "SENSOR_NATIVE_KEY_EXPORTABLE" ||
        store.OpenCount != 1 ||
        store.CreateCount != 0 ||
        store.Identity.DeleteCount != 0)
    {
        throw new InvalidOperationException("export-capable status did not fail closed");
    }
}

static void RefusesExistingIdentity()
{
    var store = new FakeKeyStore { KeyExists = true };
    try
    {
        NativeIdentityProvisioner.Provision(store);
    }
    catch (CryptographicException error) when (error.Message == "SENSOR_NATIVE_KEY_ALREADY_EXISTS")
    {
        if (
            store.CreateCount != 0 ||
            store.OpenCount != 0 ||
            store.Identity.DeleteCount != 0)
        {
            throw new InvalidOperationException("existing identity was touched");
        }
        return;
    }
    throw new InvalidOperationException("existing identity was not refused");
}

static void ProvisionsAndRetainsValidIdentity()
{
    var store = new FakeKeyStore();
    var result = NativeIdentityProvisioner.Provision(store);
    if (
        result.Provider != SensorBoundary.SoftwareProviderName ||
        !result.AclVerified ||
        !result.PrivateExportBlocked ||
        string.IsNullOrWhiteSpace(result.PublicKeyFingerprintSha256) ||
        Convert.FromBase64String(result.Proof.SignatureBase64).Length != 64 ||
        store.CreateCount != 1 ||
        store.Identity.DeleteCount != 0)
    {
        throw new InvalidOperationException("valid native identity was not retained with proof");
    }
}

static void DeletesCreatedIdentityAfterFailure()
{
    var store = new FakeKeyStore();
    store.Identity.SecurityDescriptor = ToDescriptor(
        "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GW;;;LS)");
    try
    {
        NativeIdentityProvisioner.Provision(store);
    }
    catch (CryptographicException error) when (error.Message == "SENSOR_NATIVE_KEY_ACL_INVALID")
    {
        if (store.CreateCount != 1 || store.Identity.DeleteCount != 1)
        {
            throw new InvalidOperationException("failed attempt did not clean up its own identity");
        }
        return;
    }
    throw new InvalidOperationException("invalid created identity was accepted");
}

static void DeletesCreatedIdentityWhenExportIsPossible()
{
    var store = new FakeKeyStore();
    store.Identity.PrivateExportBlocked = false;
    try
    {
        NativeIdentityProvisioner.Provision(store);
    }
    catch (CryptographicException error) when (error.Message == "SENSOR_NATIVE_KEY_EXPORTABLE")
    {
        if (store.CreateCount != 1 || store.Identity.DeleteCount != 1)
        {
            throw new InvalidOperationException("export-capable attempt was not cleaned up");
        }
        return;
    }
    throw new InvalidOperationException("export-capable created identity was accepted");
}

static void DeletesCreatedIdentityAfterBadProof()
{
    var store = new FakeKeyStore();
    store.Identity.CorruptSignature = true;
    try
    {
        NativeIdentityProvisioner.Provision(store);
    }
    catch (CryptographicException error) when (error.Message == "SENSOR_NATIVE_KEY_PROOF_INVALID")
    {
        if (store.CreateCount != 1 || store.Identity.DeleteCount != 1)
        {
            throw new InvalidOperationException("bad proof did not clean up its own identity");
        }
        return;
    }
    throw new InvalidOperationException("bad signing proof was accepted");
}

static void VerifiesNativeSignatureProfile()
{
    using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var payload = Encoding.UTF8.GetBytes("{\"schemaVersion\":1}");
    var signature = NativeSignatureProfile.Sign(signer, payload);
    if (signature.Length != 64)
    {
        throw new InvalidOperationException("signature was not fixed-width P1363");
    }
    if (!signer.VerifyData(
        payload,
        signature,
        HashAlgorithmName.SHA256,
        DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
    {
        throw new InvalidOperationException("signature did not verify");
    }
}

static void VerifiesLocalServiceStartupProof()
{
    using var identity = new FakeSensorIdentitySigner();
    var proof = NativeStartupProof.Create(identity);
    if (
        proof.PayloadSha256.Length != 64 ||
        proof.SignatureSha256.Length != 64)
    {
        throw new InvalidOperationException("startup proof hashes were not canonical SHA-256");
    }
}

static void RejectsCorruptLocalServiceStartupProof()
{
    using var identity = new FakeSensorIdentitySigner { CorruptSignature = true };
    try
    {
        NativeStartupProof.Create(identity);
    }
    catch (CryptographicException error) when (error.Message == "SENSOR_STARTUP_PROOF_INVALID")
    {
        return;
    }
    throw new InvalidOperationException("corrupt startup proof was accepted");
}

static void MatchesMinimizedFactWireVector()
{
    var vector = LoadMinimizedFactWireVector();
    var batch = NativeTelemetryFactBatch.ParseCore(vector.CoreJson);
    if (
        batch.CanonicalPayload() != vector.CanonicalPayload ||
        batch.BatchHash() != vector.BatchHash)
    {
        throw new InvalidOperationException(
            "native minimized-fact canonical payload or hash drifted");
    }
    var unicodeMission = "mission-\U0001F600-\u2028-\u2029";
    var unicodePayload = vector.CanonicalPayload.Replace(
        "mission+wire-vector-café-1",
        unicodeMission,
        StringComparison.Ordinal);
    if (
        NativeTelemetryFactBatch.ParseCore(unicodePayload).CanonicalPayload() !=
        unicodePayload)
    {
        throw new InvalidOperationException(
            "native minimized-fact Unicode payload drifted");
    }
    batch.ValidateContinuity(null);

    using var publicKey = ECDsa.Create();
    var spki = Convert.FromBase64String(vector.PublicKeySpkiBase64);
    publicKey.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
    var signature = Convert.FromBase64String(vector.SignatureBase64);
    if (
        bytesRead != spki.Length ||
        Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant() !=
            vector.CertificateFingerprintSha256 ||
        signature.Length != 64 ||
        !publicKey.VerifyData(
            Encoding.UTF8.GetBytes(vector.CanonicalPayload),
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
    {
        throw new InvalidOperationException(
            "shared minimized-fact P1363 signature did not verify");
    }
}

static void SignsCanonicalMinimizedFactPayload()
{
    var vector = LoadMinimizedFactWireVector();
    using var identity = new FakeSensorIdentitySigner();
    var boundCore = vector.CanonicalPayload.Replace(
        vector.CertificateFingerprintSha256,
        identity.Descriptor.CertificateFingerprintSha256,
        StringComparison.Ordinal);
    var batch = NativeTelemetryFactBatch.ParseCore(boundCore);
    var signed = batch.Sign(identity);
    var signature = Convert.FromBase64String(signed.SignatureBase64);
    var spki = Convert.FromBase64String(identity.Descriptor.PublicKeySpkiBase64);
    using var publicKey = ECDsa.Create();
    publicKey.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
    if (
        signed.CanonicalPayload != batch.CanonicalPayload() ||
        signed.BatchHash != batch.BatchHash() ||
        bytesRead != spki.Length ||
        signature.Length != 64 ||
        !publicKey.VerifyData(
            Encoding.UTF8.GetBytes(signed.CanonicalPayload),
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
    {
        throw new InvalidOperationException(
            "native identity did not sign the exact canonical fact payload");
    }
    try
    {
        NativeTelemetryFactBatch.ParseCore(vector.CoreJson).Sign(identity);
    }
    catch (CryptographicException error) when (
        error.Message == "SENSOR_FACT_IDENTITY_MISMATCH")
    {
        return;
    }
    throw new InvalidOperationException(
        "native fact signing accepted an unbound identity");
}

static void RejectsMinimizedFactWireDrift()
{
    var vector = LoadMinimizedFactWireVector();
    ExpectInvalidData(
        () => NativeTelemetryFactBatch.ParseCore(
            $"{vector.CanonicalPayload[..^1]},\"command\":\"whoami\"}}"),
        "SENSOR_FACT_BATCH_FIELDS_INVALID");
    ExpectInvalidData(
        () => NativeTelemetryFactBatch.ParseCore(
            vector.CanonicalPayload.Replace(
                "\"subjectClass\":\"admin-tool\"}",
                "\"subjectClass\":\"admin-tool\",\"rawPath\":\"C:\\\\private\"}",
                StringComparison.Ordinal)),
        "SENSOR_MINIMIZED_FACT_VALUES_INVALID");
    ExpectInvalidData(
        () => NativeTelemetryFactBatch.ParseCore(
            vector.CanonicalPayload.Replace(
                "\"channel\":\"eventlog-admin\"",
                "\"channel\":\"security\"",
                StringComparison.Ordinal)),
        "SENSOR_FACT_BATCH_STREAM_INVALID");
    ExpectInvalidData(
        () => NativeTelemetryFactBatch.ParseCore(
            vector.CanonicalPayload.Replace(
                "2026-07-19T13:00:00.000+01:00",
                "07/19/2026 12:00:00",
                StringComparison.Ordinal)),
        "SENSOR_MINIMIZED_FACT_TIME_INVALID");
    NativeTelemetryFactBatch.ParseCore(
        vector.CanonicalPayload
            .Replace(
                "\"batchSequence\":0",
                "\"batchSequence\":9007199254740991",
                StringComparison.Ordinal)
            .Replace(
                "2026-07-19T13:00:00.000+01:00",
                "2026-07-19T12:00:00.123456789+14:00",
                StringComparison.Ordinal));
    NativeTelemetryFactBatch.ParseCore(
        vector.CanonicalPayload.Replace(
            "2026-07-19T13:00:00.000+01:00",
            "9999-12-31T23:59:59.999999999+14:00",
            StringComparison.Ordinal));
    ExpectInvalidData(
        () => NativeTelemetryFactBatch.ParseCore(
            vector.CanonicalPayload.Replace(
                "\"batchSequence\":0",
                "\"batchSequence\":9007199254740992",
                StringComparison.Ordinal)),
        "SENSOR_FACT_BATCH_SEQUENCE_INVALID");
    ExpectInvalidData(
        () => NativeTelemetryFactBatch.ParseCore(
            vector.CanonicalPayload.Replace(
                "2026-07-19T13:00:00.000+01:00",
                "2026-07-19T12:00:00.1234567890Z",
                StringComparison.Ordinal)),
        "SENSOR_MINIMIZED_FACT_TIME_INVALID");
    ExpectInvalidData(
        () => NativeTelemetryFactBatch.ParseCore(
            vector.CanonicalPayload.Replace(
                "2026-07-19T13:00:00.000+01:00",
                "2026-07-19T12:00:00+14:01",
                StringComparison.Ordinal)),
        "SENSOR_MINIMIZED_FACT_TIME_INVALID");
    ExpectInvalidData(
        () => NativeTelemetryFactBatch.ParseCore(
            vector.CanonicalPayload.Replace(
                "2026-07-19T13:00:00.000+01:00",
                "2026-02-30T12:00:00Z",
                StringComparison.Ordinal)),
        "SENSOR_MINIMIZED_FACT_TIME_INVALID");

    var invalidOrigin = NativeTelemetryFactBatch.ParseCore(
        vector.CanonicalPayload.Replace(
            "\"batchSequence\":0",
            "\"batchSequence\":1",
            StringComparison.Ordinal));
    ExpectInvalidData(
        () => invalidOrigin.ValidateContinuity(null),
        "SENSOR_FACT_SEQUENCE_ORIGIN_INVALID");

    var head = new NativeFactStreamHead(
        "boot-wire-vector-00000001",
        0,
        vector.BatchHash);
    var sameBoot = NativeTelemetryFactBatch.ParseCore(
        WithPreviousHash(
            vector.CanonicalPayload.Replace(
                "\"batchSequence\":0",
                "\"batchSequence\":1",
                StringComparison.Ordinal),
            vector.BatchHash));
    sameBoot.ValidateContinuity(head);

    var reboot = NativeTelemetryFactBatch.ParseCore(
        WithPreviousHash(
            vector.CanonicalPayload.Replace(
                "boot-wire-vector-00000001",
                "boot-wire-vector-00000002",
                StringComparison.Ordinal),
            vector.BatchHash));
    reboot.ValidateContinuity(head);

    var badReboot = NativeTelemetryFactBatch.ParseCore(
        WithPreviousHash(
            vector.CanonicalPayload
                .Replace(
                    "\"batchSequence\":0",
                    "\"batchSequence\":1",
                    StringComparison.Ordinal)
                .Replace(
                    "boot-wire-vector-00000001",
                    "boot-wire-vector-00000002",
                    StringComparison.Ordinal),
            vector.BatchHash));
    ExpectInvalidData(
        () => badReboot.ValidateContinuity(head),
        "SENSOR_FACT_BOOT_TRANSITION_INVALID");

    var wrongPrevious = NativeTelemetryFactBatch.ParseCore(
        WithPreviousHash(
            vector.CanonicalPayload.Replace(
                "\"batchSequence\":0",
                "\"batchSequence\":1",
                StringComparison.Ordinal),
            new string('d', 64)));
    ExpectInvalidData(
        () => wrongPrevious.ValidateContinuity(head),
        "SENSOR_FACT_PREVIOUS_BATCH_MISMATCH");
}

static void ValidatesLocalSyntheticBatchProof()
{
    using var identity = new FakeSensorIdentitySigner();
    var proof = LocalSyntheticBatchProof.Create(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        new DateTime(2026, 7, 31, 8, 0, 0, DateTimeKind.Utc));
    var json = LocalSyntheticBatchProof.Serialize(proof);
    var result = LocalSyntheticBatchProof.Validate(json, identity);
    if (
        proof.Batches.Count != 2 ||
        proof.Batches[0].BatchSequence != 0 ||
        proof.Batches[0].PreviousBatchHash is not null ||
        proof.Batches[1].BatchSequence != 1 ||
        !StringComparer.Ordinal.Equals(
            proof.Batches[1].PreviousBatchHash,
            proof.Batches[0].BatchHash) ||
        result.BatchCount != 2 ||
        !result.SyntheticOnly ||
        result.EventReaderEnabled ||
        result.NetworkTransportEnabled ||
        result.InboundListenerEnabled ||
        result.CommandChannelEnabled ||
        !StringComparer.Ordinal.Equals(
            result.CertificateFingerprintSha256,
            identity.Descriptor.CertificateFingerprintSha256))
    {
        throw new InvalidOperationException(
            "local synthetic signed-batch proof was not exact");
    }
}

static void RejectsLocalSyntheticBatchProofDrift()
{
    using var identity = new FakeSensorIdentitySigner();
    var proof = LocalSyntheticBatchProof.Create(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        new DateTime(2026, 7, 31, 8, 0, 0, DateTimeKind.Utc));
    var json = LocalSyntheticBatchProof.Serialize(proof);

    ExpectInvalidData(
        () => LocalSyntheticBatchProof.Validate(
            json.Replace(
                "\"networkTransportEnabled\":false",
                "\"networkTransportEnabled\":true",
                StringComparison.Ordinal),
            identity),
        "SENSOR_LOCAL_PROOF_INVALID");
    ExpectInvalidData(
        () => LocalSyntheticBatchProof.Validate(
            json.Replace(
                "\"batches\":[",
                "\"unexpectedCommand\":\"whoami\",\"batches\":[",
                StringComparison.Ordinal),
            identity),
        "SENSOR_LOCAL_PROOF_FIELDS_INVALID");

    var batchHash = proof.Batches[1].BatchHash;
    var replacement = batchHash[0] == 'a'
        ? $"b{batchHash[1..]}"
        : $"a{batchHash[1..]}";
    ExpectInvalidData(
        () => LocalSyntheticBatchProof.Validate(
            json.Replace(batchHash, replacement, StringComparison.Ordinal),
            identity),
        "SENSOR_LOCAL_PROOF_BATCH_INVALID");
}

static void RejectsLocalSyntheticProofOutsideLocalService()
{
    using var identity = new FakeSensorIdentitySigner();
    try
    {
        _ = LocalSyntheticBatchProof.Create(
            identity,
            new FakeSensorServiceIdentity("S-1-5-21-1000"),
            new DateTime(2026, 7, 31, 8, 0, 0, DateTimeKind.Utc));
    }
    catch (InvalidOperationException error) when (
        error.Message == "SENSOR_LOCAL_PROOF_LOCALSERVICE_REQUIRED")
    {
        return;
    }
    throw new InvalidOperationException(
        "local synthetic proof was created outside LocalService");
}

static void ValidatesLocalProofNativeFileAccess()
{
    const uint unsafeWriteAccess =
        0x00000004 | // FILE_APPEND_DATA
        0x00000010 | // FILE_WRITE_EA
        0x00000100 | // FILE_WRITE_ATTRIBUTES
        0x00010000 | // DELETE
        0x00040000 | // WRITE_DAC
        0x00080000;  // WRITE_OWNER
    if (
        LocalProofNativeFileAccess.DesiredAccess != 0x00000002 ||
        (LocalProofNativeFileAccess.DesiredAccess & unsafeWriteAccess) != 0 ||
        LocalProofNativeFileAccess.ShareMode != 0x00000001 ||
        LocalProofNativeFileAccess.CreationDisposition != 3 ||
        LocalProofNativeFileAccess.FlagsAndAttributes != 0x80000080)
    {
        throw new InvalidOperationException(
            "local proof native file access exceeded FILE_WRITE_DATA");
    }
}

static GenuineScmEventMetadata ValidGenuineScmMetadata() =>
    new(
        NativeGenuineScmEventReader.ProviderName,
        NativeGenuineScmEventReader.EventId,
        NativeGenuineScmEventReader.Level,
        new DateTimeOffset(2026, 8, 2, 20, 36, 45, TimeSpan.FromHours(1)),
        248_663);

static void ValidatesGenuineScmBatchProof()
{
    using var identity = new FakeSensorIdentitySigner();
    var reader = new FakeGenuineScmEventReader(ValidGenuineScmMetadata());
    var salt = Enumerable.Range(1, GenuineScmBatchProof.SaltBytes)
        .Select(value => (byte)value)
        .ToArray();
    var proof = GenuineScmBatchProof.Create(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        reader,
        salt,
        new DateTime(2026, 8, 2, 19, 36, 29, DateTimeKind.Utc),
        new DateTime(2026, 8, 2, 19, 36, 49, DateTimeKind.Utc)) ??
        throw new InvalidOperationException("genuine proof was not created");
    var result = GenuineScmBatchProof.Validate(
        GenuineScmBatchProof.Serialize(proof),
        identity);
    _ = GenuineScmBatchProof.ValidateForManifest(
        GenuineScmBatchProof.Serialize(proof),
        identity,
        new DateTime(2026, 8, 2, 19, 36, 29, DateTimeKind.Utc));
    ExpectInvalidData(
        () => GenuineScmBatchProof.ValidateForManifest(
            GenuineScmBatchProof.Serialize(proof),
            identity,
            new DateTime(2026, 8, 2, 19, 36, 30, DateTimeKind.Utc)),
        "SENSOR_GENUINE_PROOF_MANIFEST_MISMATCH");
    ExpectInvalidData(
        () => NativeTelemetryFactBatch.ParseCore(
            proof.Batch.CanonicalPayload.Replace(
                "\"outcome\":\"unknown\"",
                "\"originZone\":\"user-writable\",\"outcome\":\"unknown\"",
                StringComparison.Ordinal)),
        "SENSOR_SCM_FACT_PROFILE_INVALID");
    var noncanonicalPayload = $" {proof.Batch.CanonicalPayload}";
    var noncanonicalProof = proof with
    {
        Batch = proof.Batch with
        {
            CanonicalPayload = noncanonicalPayload,
            SignatureBase64 = identity.SignUtf8Payload(noncanonicalPayload)
        }
    };
    ExpectInvalidData(
        () => GenuineScmBatchProof.Validate(
            GenuineScmBatchProof.Serialize(noncanonicalProof),
            identity),
        "SENSOR_GENUINE_PROOF_BATCH_INVALID");
    var wrongFingerprintPayload = proof.Batch.CanonicalPayload.Replace(
        identity.Descriptor.CertificateFingerprintSha256,
        new string('a', 64),
        StringComparison.Ordinal);
    var wrongFingerprintCore = NativeTelemetryFactBatch.ParseCore(
        wrongFingerprintPayload);
    var wrongFingerprintProof = proof with
    {
        Batch = proof.Batch with
        {
            CanonicalPayload = wrongFingerprintCore.CanonicalPayload(),
            BatchHash = wrongFingerprintCore.BatchHash(),
            SignatureBase64 = identity.SignUtf8Payload(
                wrongFingerprintCore.CanonicalPayload())
        }
    };
    ExpectInvalidData(
        () => GenuineScmBatchProof.Validate(
            GenuineScmBatchProof.Serialize(wrongFingerprintProof),
            identity),
        "SENSOR_GENUINE_PROOF_CORE_INVALID");
    if (
        reader.ReadCount != 1 ||
        result.BatchCount != 1 ||
        result.FactCount != 1 ||
        result.EventsRead != 1 ||
        !result.GenuineEventRead ||
        result.RawEventContentRead ||
        !result.EventReaderEnabled ||
        result.NetworkTransportEnabled ||
        result.InboundListenerEnabled ||
        result.PollingEnabled ||
        result.CommandChannelEnabled ||
        result.OccurredAtUtc != "2026-08-02T19:36:45.0000000Z")
    {
        throw new InvalidOperationException(
            "genuine SCM proof exceeded its one-fact boundary");
    }
}

static LocalSyntheticSignedBatch CreateLoopbackTransportBatch()
{
    using var identity = new FakeSensorIdentitySigner();
    return (GenuineScmBatchProof.Create(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        new FakeGenuineScmEventReader(ValidGenuineScmMetadata()),
        Enumerable.Range(1, GenuineScmBatchProof.SaltBytes)
            .Select(value => (byte)value)
            .ToArray(),
        new DateTime(2026, 8, 2, 19, 36, 29, DateTimeKind.Utc),
        new DateTime(2026, 8, 2, 19, 36, 49, DateTimeKind.Utc)) ??
        throw new InvalidOperationException("genuine proof was not created")).Batch;
}

static string ValidLoopbackReceipt(LocalSyntheticSignedBatch batch) =>
    JsonSerializer.Serialize(new
    {
        receipt = new
        {
            schemaVersion = 1,
            status = "accepted",
            batchHash = batch.BatchHash,
            batchSequence = batch.BatchSequence,
            factCount = 1
        }
    });

static HttpResponseMessage LoopbackResponse(
    LocalSyntheticSignedBatch batch,
    string? body = null,
    HttpStatusCode status = HttpStatusCode.Accepted,
    string mediaType = "application/json",
    string charSet = "utf-8")
{
    var response = new HttpResponseMessage(status)
    {
        Content = new StringContent(
            body ?? ValidLoopbackReceipt(batch),
            Encoding.UTF8,
            mediaType)
    };
    response.Content.Headers.ContentType!.CharSet = charSet;
    return response;
}

static void ValidatesLoopbackFactTransport()
{
    var batch = CreateLoopbackTransportBatch();
    var handler = new FakeLoopbackHandler(
        async (request, cancellationToken) =>
        {
            if (
                request.Method != HttpMethod.Post ||
                request.RequestUri?.AbsoluteUri != LoopbackFactTransport.Destination ||
                request.Headers.Any() ||
                request.Content?.Headers.ContentType?.MediaType != "application/json" ||
                request.Content.Headers.ContentType.CharSet != "utf-8")
            {
                throw new InvalidOperationException("loopback request boundary drifted");
            }
            var body = await request.Content.ReadAsStringAsync(cancellationToken);
            using var parsed = JsonDocument.Parse(body);
            var names = parsed.RootElement.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal);
            if (
                names.Count != 16 ||
                !names.Contains("batchHash") ||
                !names.Contains("signatureBase64") ||
                names.Contains("proof") ||
                names.Contains("command") ||
                parsed.RootElement.GetProperty("facts").GetArrayLength() != 1)
            {
                throw new InvalidOperationException("loopback request was not exact");
            }
            return LoopbackResponse(batch);
        });
    using var transport = new LoopbackFactTransport(handler);
    var receipt = transport.SendOnceAsync(batch, CancellationToken.None)
        .GetAwaiter().GetResult();
    if (
        handler.SendCount != 1 ||
        receipt.SchemaVersion != 1 ||
        receipt.Status != "accepted" ||
        receipt.BatchHash != batch.BatchHash ||
        receipt.BatchSequence != 0 ||
        receipt.FactCount != 1)
    {
        throw new InvalidOperationException("loopback receipt was not exact");
    }
}

static void RejectsLoopbackFactTransportDrift()
{
    var batch = CreateLoopbackTransportBatch();
    var cases = new (HttpResponseMessage Response, string Error)[]
    {
        (LoopbackResponse(batch, status: HttpStatusCode.OK),
            "SENSOR_LOOPBACK_RESPONSE_STATUS_INVALID"),
        (LoopbackResponse(batch, mediaType: "text/plain"),
            "SENSOR_LOOPBACK_RESPONSE_CONTENT_TYPE_INVALID"),
        (LoopbackResponse(batch, charSet: "utf-16"),
            "SENSOR_LOOPBACK_RESPONSE_CONTENT_TYPE_INVALID"),
        (LoopbackResponse(
            batch,
            ValidLoopbackReceipt(batch).Replace(
                "\"factCount\":1",
                "\"factCount\":1,\"command\":\"whoami\"",
                StringComparison.Ordinal)),
            "SENSOR_LOOPBACK_RECEIPT_FIELDS_INVALID"),
        (LoopbackResponse(
            batch,
            ValidLoopbackReceipt(batch).Replace(
                batch.BatchHash,
                new string('a', 64),
                StringComparison.Ordinal)),
            "SENSOR_LOOPBACK_RECEIPT_INVALID"),
        (LoopbackResponse(batch, new string('x', LoopbackFactTransport.MaximumResponseBytes + 1)),
            "SENSOR_LOOPBACK_RESPONSE_SIZE_INVALID")
    };

    foreach (var item in cases)
    {
        var handler = new FakeLoopbackHandler((_, _) => Task.FromResult(item.Response));
        using var transport = new LoopbackFactTransport(handler);
        ExpectInvalidData(
            () => transport.SendOnceAsync(batch, CancellationToken.None)
                .GetAwaiter().GetResult(),
            item.Error);
        if (handler.SendCount != 1)
        {
            throw new InvalidOperationException("loopback sender retried a failed request");
        }
    }
}

static void RejectsLoopbackFactTransportInput()
{
    var batch = CreateLoopbackTransportBatch();
    var cases = new[]
    {
        batch with { BatchSequence = 1 },
        batch with { PreviousBatchHash = new string('b', 64) },
        batch with { BatchHash = new string('c', 64) },
        batch with { SignatureBase64 = Convert.ToBase64String(new byte[63]) },
        batch with
        {
            CanonicalPayload = batch.CanonicalPayload.Replace(
                "\"provider\":\"windows-scm\"",
                "\"provider\":\"windows-eventlog\"",
                StringComparison.Ordinal)
        }
    };
    foreach (var unsafeBatch in cases)
    {
        var handler = new FakeLoopbackHandler(
            (_, _) => throw new InvalidOperationException("network must stay closed"));
        using var transport = new LoopbackFactTransport(handler);
        try
        {
            _ = transport.SendOnceAsync(unsafeBatch, CancellationToken.None)
                .GetAwaiter().GetResult();
        }
        catch (InvalidDataException)
        {
            if (handler.SendCount == 0)
            {
                continue;
            }
        }
        throw new InvalidOperationException("unsafe loopback input reached the network");
    }
}

static void ValidatesLoopbackFactTransportBoundary()
{
    using (var handler = LoopbackFactTransport.CreateFixedHandler())
    {
        if (
            handler.AllowAutoRedirect ||
            handler.UseProxy ||
            handler.UseCookies ||
            handler.UseDefaultCredentials ||
            handler.AutomaticDecompression != DecompressionMethods.None ||
            handler.MaxConnectionsPerServer != 1 ||
            LoopbackFactTransport.TimeoutMilliseconds != 5_000 ||
            LoopbackFactTransport.MaximumRequestBytes != 32_768 ||
            LoopbackFactTransport.MaximumResponseBytes != 1_024)
        {
            throw new InvalidOperationException("loopback HTTP handler was not fail-closed");
        }
    }

    var batch = CreateLoopbackTransportBatch();
    var handler2 = new FakeLoopbackHandler(
        async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        });
    using var transport = new LoopbackFactTransport(handler2);
    using var cancellation = new CancellationTokenSource();
    cancellation.Cancel();
    try
    {
        _ = transport.SendOnceAsync(batch, cancellation.Token)
            .GetAwaiter().GetResult();
    }
    catch (OperationCanceledException) when (handler2.SendCount == 1)
    {
        return;
    }
    throw new InvalidOperationException("loopback cancellation was not preserved");
}

static (
    string FinalJson,
    string CapabilityProofJson,
    string GenuineProofJson,
    InstallManifestBinding Manifest,
    DateTime ManifestGeneratedAt,
    DateTime Now)
    EndpointDeliveryFixture(ISensorIdentitySigner identity)
{
    var fixture = FinalBindingFixture(identity);
    var commit = new string('a', 40);
    var bindingHash = new string('b', 64);
    var now = new DateTime(2026, 8, 3, 12, 2, 0, DateTimeKind.Utc);
    var manifestGeneratedAt = new DateTime(
        2026, 8, 3, 11, 59, 0, DateTimeKind.Utc);
    var final = EndpointBindingLifecycle.FinalizeBinding(
        fixture.FinalInput,
        fixture.Pending,
        fixture.Proof,
        identity.Descriptor,
        commit,
        new DateTime(2026, 8, 3, 12, 1, 0, DateTimeKind.Utc));
    var genuine = GenuineScmBatchProof.Create(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        new FakeGenuineScmEventReader(new GenuineScmEventMetadata(
            NativeGenuineScmEventReader.ProviderName,
            NativeGenuineScmEventReader.EventId,
            NativeGenuineScmEventReader.Level,
            new DateTimeOffset(new DateTime(
                2026, 8, 3, 12, 0, 30, DateTimeKind.Utc)),
            73)),
        Enumerable.Range(1, GenuineScmBatchProof.SaltBytes)
            .Select(value => (byte)value).ToArray(),
        manifestGeneratedAt,
        new DateTime(2026, 8, 3, 12, 1, 0, DateTimeKind.Utc)) ??
        throw new InvalidOperationException("delivery genuine proof missing");
    return (
        EndpointBindingLifecycle.SerializeFinal(final),
        EndpointBindingLifecycle.SerializeCapabilityProof(fixture.Proof),
        GenuineScmBatchProof.Serialize(genuine),
        new InstallManifestBinding(
            commit,
            identity.Descriptor.CertificateFingerprintSha256,
            bindingHash),
        manifestGeneratedAt,
        now);
}

static void ValidatesEndpointOneShotDelivery()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = EndpointDeliveryFixture(identity);
    var batch = EndpointOneShotDelivery.CreateBatch(
        fixture.FinalJson,
        fixture.CapabilityProofJson,
        fixture.GenuineProofJson,
        identity,
        fixture.Manifest,
        fixture.ManifestGeneratedAt,
        fixture.Now);
    using var core = JsonDocument.Parse(batch.CanonicalPayload);
    var root = core.RootElement;
    if (
        root.GetProperty("missionId").GetString() !=
            "11111111-1111-4111-8111-111111111111" ||
        root.GetProperty("connectorId").GetString() !=
            "connector-22222222-2222-4222-8222-222222222222" ||
        root.GetProperty("endpointId").GetString() !=
            "endpoint-33333333-3333-4333-8333-333333333333" ||
        root.GetProperty("capabilitySnapshotId").GetString() !=
            "capability-55555555-5555-4555-8555-555555555555" ||
        root.GetProperty("facts").GetArrayLength() != 1 ||
        batch.CanonicalPayload.Contains("local-gate-b1", StringComparison.Ordinal))
        throw new InvalidOperationException("delivery batch was not exactly rebound");
    var final = EndpointBindingLifecycle.ValidateFinal(
        fixture.FinalJson,
        fixture.CapabilityProofJson,
        identity.Descriptor,
        fixture.Manifest.Commit,
        fixture.Now);
    var receipt = new LoopbackFactReceipt(1, "accepted", batch.BatchHash, 0, 1);
    var document = EndpointOneShotDelivery.Accepted(
        batch, receipt, final, fixture.Manifest, fixture.Now);
    var validated = EndpointOneShotDelivery.Validate(
        document, batch, final, fixture.Manifest, requireAccepted: true);
    if (validated.State != "accepted" || !validated.NetworkAttempted ||
        validated.AutomaticRetryEnabled || validated.RemoteTransportEnabled ||
        validated.InboundListenerEnabled || validated.PollingEnabled ||
        validated.CommandChannelEnabled)
        throw new InvalidOperationException("delivery receipt exceeded one-shot authority");
}

static void RejectsEndpointOneShotDeliveryDrift()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = EndpointDeliveryFixture(identity);
    ExpectInvalidData(
        () => EndpointOneShotDelivery.CreateBatch(
            fixture.FinalJson,
            fixture.CapabilityProofJson,
            fixture.GenuineProofJson,
            identity,
            fixture.Manifest,
            fixture.ManifestGeneratedAt,
            new DateTime(2026, 8, 3, 12, 5, 0, DateTimeKind.Utc)),
        "SENSOR_DELIVERY_CAPABILITY_STALE");
    var batch = EndpointOneShotDelivery.CreateBatch(
        fixture.FinalJson,
        fixture.CapabilityProofJson,
        fixture.GenuineProofJson,
        identity,
        fixture.Manifest,
        fixture.ManifestGeneratedAt,
        fixture.Now);
    var final = EndpointBindingLifecycle.ValidateFinal(
        fixture.FinalJson,
        fixture.CapabilityProofJson,
        identity.Descriptor,
        fixture.Manifest.Commit,
        fixture.Now);
    var document = EndpointOneShotDelivery.Accepted(
        batch,
        new LoopbackFactReceipt(1, "accepted", batch.BatchHash, 0, 1),
        final,
        fixture.Manifest,
        fixture.Now);
    ExpectInvalidData(
        () => EndpointOneShotDelivery.Validate(
            document.Replace(
                "\"automaticRetryEnabled\":false",
                "\"automaticRetryEnabled\":true",
                StringComparison.Ordinal),
            batch, final, fixture.Manifest, requireAccepted: true),
        "SENSOR_DELIVERY_DOCUMENT_INVALID");
}

static void WritesEndpointDeliveryOnce()
{
    using var identity = new FakeSensorIdentitySigner();
    var fixture = EndpointDeliveryFixture(identity);
    var bindingStore = new FakeEndpointBindingStore
    {
        Binding = fixture.FinalJson,
        CapabilityProof = fixture.CapabilityProofJson
    };
    var genuineStore = new FakeGenuineProofStore(fixture.GenuineProofJson);
    var deliveryStore = new FakeEndpointDeliveryStore();
    var transport = new FakeEndpointDeliveryTransport();
    var worker = new EndpointOneShotDeliveryWorker(
        identity,
        bindingStore,
        genuineStore,
        deliveryStore,
        new FakeInstallManifestBindingReader(fixture.Manifest),
        new FakeManifestTimestampReader(fixture.ManifestGeneratedAt),
        transport,
        new FixedTestTimeProvider(fixture.Now),
        NullLogger<EndpointOneShotDeliveryWorker>.Instance);
    worker.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
    worker.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
    if (transport.SendCount != 1 || deliveryStore.WriteCount != 2 ||
        deliveryStore.Document is null)
        throw new InvalidOperationException("delivery worker retried or lost its receipt");

    var batch = EndpointOneShotDelivery.CreateBatch(
        fixture.FinalJson, fixture.CapabilityProofJson, fixture.GenuineProofJson,
        identity, fixture.Manifest, fixture.ManifestGeneratedAt, fixture.Now);
    var final = EndpointBindingLifecycle.ValidateFinal(
        fixture.FinalJson, fixture.CapabilityProofJson, identity.Descriptor,
        fixture.Manifest.Commit, fixture.Now);
    var claimedStore = new FakeEndpointDeliveryStore
    {
        Document = EndpointOneShotDelivery.Claimed(
            batch, final, fixture.Manifest, fixture.Now)
    };
    var claimedTransport = new FakeEndpointDeliveryTransport();
    var claimedWorker = new EndpointOneShotDeliveryWorker(
        identity, bindingStore, genuineStore, claimedStore,
        new FakeInstallManifestBindingReader(fixture.Manifest),
        new FakeManifestTimestampReader(fixture.ManifestGeneratedAt),
        claimedTransport, new FixedTestTimeProvider(fixture.Now),
        NullLogger<EndpointOneShotDeliveryWorker>.Instance);
    var claimedBlocked = false;
    try
    {
        claimedWorker.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
    }
    catch (InvalidDataException error) when (
        error.Message == "SENSOR_DELIVERY_PREVIOUS_INCOMPLETE" &&
        claimedTransport.SendCount == 0)
    {
        claimedBlocked = true;
    }
    if (!claimedBlocked)
        throw new InvalidOperationException("claimed delivery was retried");

    var failedStore = new FakeEndpointDeliveryStore();
    var failedTransport = new FakeEndpointDeliveryTransport
    {
        Failure = new HttpRequestException("offline")
    };
    var failedWorker = new EndpointOneShotDeliveryWorker(
        identity,
        bindingStore,
        genuineStore,
        failedStore,
        new FakeInstallManifestBindingReader(fixture.Manifest),
        new FakeManifestTimestampReader(fixture.ManifestGeneratedAt),
        failedTransport,
        new FixedTestTimeProvider(fixture.Now),
        NullLogger<EndpointOneShotDeliveryWorker>.Instance);
    try
    {
        failedWorker.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
    }
    catch (HttpRequestException)
    {
        try
        {
            failedWorker.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (InvalidDataException error) when (
            error.Message == "SENSOR_DELIVERY_PREVIOUS_FAILURE" &&
            failedTransport.SendCount == 1 && failedStore.WriteCount == 2)
        {
            return;
        }
    }
    throw new InvalidOperationException("failed delivery was automatically retried");
}

static void ValidatesGenuineScmNoMatch()
{
    using var identity = new FakeSensorIdentitySigner();
    var reader = new FakeGenuineScmEventReader(null);
    var result = GenuineScmBatchProof.Create(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        reader,
        new byte[GenuineScmBatchProof.SaltBytes],
        new DateTime(2026, 8, 2, 19, 36, 29, DateTimeKind.Utc),
        new DateTime(2026, 8, 2, 19, 36, 49, DateTimeKind.Utc));
    if (result is not null || reader.ReadCount != 1)
    {
        throw new InvalidOperationException("no-match fabricated a fact");
    }
    var staleReader = new FakeGenuineScmEventReader(
        ValidGenuineScmMetadata() with
        {
            TimeCreated = new DateTimeOffset(
                2026, 8, 2, 19, 0, 0, TimeSpan.Zero)
        });
    var stale = GenuineScmBatchProof.Create(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        staleReader,
        new byte[GenuineScmBatchProof.SaltBytes],
        new DateTime(2026, 8, 2, 19, 36, 29, DateTimeKind.Utc),
        new DateTime(2026, 8, 2, 19, 36, 49, DateTimeKind.Utc));
    if (stale is not null || staleReader.ReadCount != 1)
    {
        throw new InvalidOperationException("stale record fabricated a fact");
    }
}

static void RejectsGenuineScmMetadataDrift()
{
    using var identity = new FakeSensorIdentitySigner();
    var valid = ValidGenuineScmMetadata();
    var cases = new[]
    {
        valid with { ProviderName = "Other" },
        valid with { EventId = 7040 },
        valid with { Level = 3 },
        valid with { RecordId = 0 },
        valid with { TimeCreated = new DateTimeOffset(2026, 8, 2, 19, 37, 0, TimeSpan.Zero) }
    };
    foreach (var metadata in cases)
    {
        ExpectInvalidData(
            () => GenuineScmBatchProof.Create(
                identity,
                new FakeSensorServiceIdentity(
                    NativeKeyAccessPolicy.LocalServiceSid),
                new FakeGenuineScmEventReader(metadata),
                new byte[GenuineScmBatchProof.SaltBytes],
                new DateTime(2026, 8, 2, 19, 36, 29, DateTimeKind.Utc),
                new DateTime(2026, 8, 2, 19, 36, 49, DateTimeKind.Utc)),
            "SENSOR_GENUINE_EVENT_METADATA_INVALID");
    }
    var rollbackReader = new FakeGenuineScmEventReader(null);
    try
    {
        _ = GenuineScmBatchProof.Create(
            identity,
            new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
            rollbackReader,
            new byte[GenuineScmBatchProof.SaltBytes],
            new DateTime(2026, 8, 2, 19, 36, 50, DateTimeKind.Utc),
            new DateTime(2026, 8, 2, 19, 36, 49, DateTimeKind.Utc));
    }
    catch (InvalidOperationException error) when (
        error.Message == "SENSOR_GENUINE_PROOF_BOUNDARY_INVALID" &&
        rollbackReader.ReadCount == 0)
    {
        return;
    }
    throw new InvalidOperationException(
        "manifest clock rollback did not fail before the event query");
}

static void ValidatesGenuineScmSourceHash()
{
    var metadata = ValidGenuineScmMetadata();
    var firstSalt = Enumerable.Repeat((byte)0x11, GenuineScmBatchProof.SaltBytes)
        .ToArray();
    var secondSalt = Enumerable.Repeat((byte)0x22, GenuineScmBatchProof.SaltBytes)
        .ToArray();
    const string occurredAt = "2026-08-02T19:36:45.0000000Z";
    var first = GenuineScmBatchProof.SourceRecordIdHash(
        metadata,
        occurredAt,
        firstSalt);
    var repeated = GenuineScmBatchProof.SourceRecordIdHash(
        metadata,
        occurredAt,
        firstSalt);
    var otherInstall = GenuineScmBatchProof.SourceRecordIdHash(
        metadata,
        occurredAt,
        secondSalt);
    var otherTime = GenuineScmBatchProof.SourceRecordIdHash(
        metadata,
        "2026-08-02T19:36:46.0000000Z",
        firstSalt);
    if (
        first.Length != 64 ||
        first != repeated ||
        first == otherInstall ||
        first == otherTime)
    {
        throw new InvalidOperationException(
            "genuine source hash was reversible or cross-install stable");
    }
}

static void ValidatesGenuineScmReaderBoundary()
{
    if (
        NativeGenuineScmEventReader.LogName != "System" ||
        NativeGenuineScmEventReader.ProviderName != "Service Control Manager" ||
        NativeGenuineScmEventReader.EventId != 7045 ||
        NativeGenuineScmEventReader.Level != 4 ||
        NativeGenuineScmEventReader.MaximumRecords != 1 ||
        NativeGenuineScmEventReader.MaximumReadMilliseconds != 2_000 ||
        NativeGenuineScmEventReader.FixedQuery !=
            "*[System[Provider[@Name='Service Control Manager'] and EventID=7045 and Level=4]]")
    {
        throw new InvalidOperationException("genuine SCM query boundary drifted");
    }
}

static string WithPreviousHash(string payload, string previousHash) =>
    payload.Replace(
        "\"previousBatchHash\":null",
        $"\"previousBatchHash\":\"{previousHash}\"",
        StringComparison.Ordinal);

static void ExpectInvalidData(Action action, string expected)
{
    try
    {
        action();
    }
    catch (InvalidDataException error) when (error.Message == expected)
    {
        return;
    }
    throw new InvalidOperationException(
        $"unsafe minimized-fact input did not fail with {expected}");
}

static NativeTelemetryWireVector LoadMinimizedFactWireVector()
{
    var path = Path.Combine(
        AppContext.BaseDirectory,
        "minimized-fact-batch-v1.json");
    using var document = JsonDocument.Parse(File.ReadAllText(path));
    var root = document.RootElement;
    if (root.GetProperty("vectorVersion").GetInt32() != 1)
    {
        throw new InvalidOperationException(
            "unsupported minimized-fact wire vector");
    }
    return new NativeTelemetryWireVector(
        root.GetProperty("core").GetRawText(),
        root.GetProperty("core")
            .GetProperty("certificateFingerprintSha256")
            .GetString() ??
            throw new InvalidOperationException("wire fingerprint missing"),
        root.GetProperty("canonicalPayload").GetString() ??
            throw new InvalidOperationException("wire payload missing"),
        root.GetProperty("batchHash").GetString() ??
            throw new InvalidOperationException("wire hash missing"),
        root.GetProperty("publicKeySpkiBase64").GetString() ??
            throw new InvalidOperationException("wire public key missing"),
        root.GetProperty("signatureBase64").GetString() ??
            throw new InvalidOperationException("wire signature missing"));
}

static void AcceptsDataOnlyReceipt()
{
    SensorBoundary.ValidateReceiptFields(new[] { "receiptHash", "batchId", "acceptedSequence" });
    try
    {
        SensorBoundary.ValidateReceiptFields(
            new[] { "receiptHash", "batchId", "acceptedSequence", "command" });
    }
    catch (InvalidDataException error) when (error.Message == "SENSOR_RECEIPT_FIELDS_INVALID")
    {
        return;
    }
    throw new InvalidOperationException("response action field was accepted");
}

static void ValidatesSourceReadinessPlan()
{
    var plan = WindowsEventSourceReadiness.BuildPlan();
    var expectedFields = new[]
    {
        "providerName",
        "eventId",
        "level",
        "timeCreatedUtc",
        "recordId"
    };
    if (
        plan.SchemaVersion != 1 ||
        plan.ProbeContext != "operator-session-metadata-only" ||
        plan.ServiceIdentityValidated ||
        plan.RuntimeCollectionEnabled ||
        plan.TransportEnabled ||
        plan.InboundListenerEnabled ||
        plan.CommandChannelEnabled ||
        plan.ArbitraryChannelsAllowed ||
        plan.RawEventContentAllowed ||
        plan.EventsRead != 0 ||
        plan.Sources.Count != 2 ||
        plan.Sources[0].SourceId != "windows-system" ||
        plan.Sources[0].LogName != "System" ||
        plan.Sources[1].SourceId != "windows-application" ||
        plan.Sources[1].LogName != "Application" ||
        plan.Sources.Any(
            source =>
                !source.PermittedFutureEventMetadataFields.SequenceEqual(
                    expectedFields,
                    StringComparer.Ordinal)))
    {
        throw new InvalidOperationException(
            "source-readiness plan exceeded the metadata-only boundary");
    }

    if (
        WindowsEventSourceReadinessCommandParser.Parse(["plan"]) !=
            WindowsEventSourceReadinessCommand.Plan ||
        WindowsEventSourceReadinessCommandParser.Parse(["check"]) !=
            WindowsEventSourceReadinessCommand.Check ||
        WindowsEventSourceReadinessCommandParser.Parse(
            ["security-4663-plan"]) !=
            WindowsEventSourceReadinessCommand.Security4663Plan ||
        WindowsEventSourceReadinessCommandParser.Parse(
            ["security-4663-check"]) !=
            WindowsEventSourceReadinessCommand.Security4663Check)
    {
        throw new InvalidOperationException(
            "source-readiness command parsed incorrectly");
    }
    foreach (var arguments in new[]
    {
        Array.Empty<string>(),
        new[] { "collect" },
        new[] { "check", "Security" },
        new[] { "shell" }
    })
    {
        try
        {
            WindowsEventSourceReadinessCommandParser.Parse(arguments);
        }
        catch (InvalidDataException error) when (
            error.Message == "SENSOR_SOURCE_READINESS_COMMAND_INVALID")
        {
            continue;
        }
        throw new InvalidOperationException(
            "unsafe source-readiness command was accepted");
    }
}

static void ValidatesSecurity4663MachineReadinessPlan()
{
    var plan = Security4663MachineReadiness.BuildPlan();
    Security4663MachineReadiness.ValidatePlan(plan);
    if (
        plan.SchemaVersion != 1 ||
        plan.Checkpoint != "gate-c2d-security-4663-machine-readiness" ||
        plan.ServiceName != "WARRoomWindowsSensor" ||
        plan.StartIdentity != @"NT AUTHORITY\LocalService" ||
        plan.LocalServiceSid != "S-1-5-19" ||
        plan.LogName != "Security" ||
        plan.ProviderName != "Microsoft-Windows-Security-Auditing" ||
        plan.EventId != 4663 ||
        plan.Level != 0 ||
        plan.RequiredChannelReadAce != "(A;;0x1;;;LS)" ||
        plan.AuditSubcategory != "File System" ||
        !plan.RequiresElevation ||
        !plan.RequiresSecurityLogReadAccess ||
        plan.SecurityLogWriteAllowed ||
        plan.SecurityLogClearAllowed ||
        plan.EventLogReadersMembershipAllowed ||
        plan.SeSecurityPrivilegeAssignmentAllowed ||
        !plan.AuditSuccessRequired ||
        plan.AuditFailureRequired ||
        plan.RealCredentialLocationsAllowed ||
        plan.ReparsePointsAllowed ||
        plan.ChangesChannelAccess ||
        plan.ChangesAuditPolicy ||
        plan.ChangesTargetSacl ||
        plan.ReadsEvents ||
        plan.EventsRead != 0 ||
        plan.RuntimeCollectionEnabled ||
        plan.TransportEnabled ||
        plan.InboundListenerEnabled ||
        plan.CommandChannelEnabled ||
        plan.Targets.Count != 3 ||
        plan.Targets.Select(target => target.ProfileId).Distinct().Count() != 3 ||
        plan.Targets.Any(target =>
            !target.InertTargetPath.StartsWith(
                @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\",
                StringComparison.Ordinal) ||
            target.AuditPrincipalSid != "S-1-1-0" ||
            !target.SuccessAuditRequired ||
            target.FailureAuditRequired) ||
        plan.Targets[0].RequiredAccessMask != "0x00000001" ||
        plan.Targets[1].RequiredAccessMask != "0x00000001" ||
        plan.Targets[2].RequiredAccessMask != "0x00000100")
    {
        throw new InvalidOperationException(
            "SENSOR_C2D_SECURITY_4663_READINESS_PLAN_INVALID");
    }
}

static void RejectsSecurity4663MachineReadinessPlanDrift()
{
    var plan = Security4663MachineReadiness.BuildPlan();
    var driftedPlans = new[]
    {
        plan with { StartIdentity = @"NT AUTHORITY\SYSTEM" },
        plan with { RequiredChannelReadAce = "(A;;0x7;;;LS)" },
        plan with { EventLogReadersMembershipAllowed = true },
        plan with { SeSecurityPrivilegeAssignmentAllowed = true },
        plan with { RealCredentialLocationsAllowed = true },
        plan with { ChangesChannelAccess = true },
        plan with { ReadsEvents = true, EventsRead = 1 },
        plan with { RuntimeCollectionEnabled = true }
    };
    foreach (var drifted in driftedPlans)
    {
        AssertThrows<InvalidDataException>(
            () => Security4663MachineReadiness.ValidatePlan(drifted),
            "SENSOR_C2D_SECURITY_4663_READINESS_PLAN_INVALID");
    }

    AssertThrows<InvalidDataException>(
        () => Security4663MachineReadiness.ValidatePlan(
            plan with
            {
                Targets = plan.Targets
                    .Select((target, index) => index == 0
                        ? target with
                        {
                            InertTargetPath = @"C:\Users\operator\real-secret"
                        }
                        : target)
                    .ToArray()
            }),
        "SENSOR_C2D_SECURITY_4663_READINESS_PLAN_INVALID");
}

static void ValidatesSecurity4663OneShotPlan()
{
    var plan = Security4663OneShotMachinePlan.BuildPlan();
    Security4663OneShotMachinePlan.ValidatePlan(plan);
    if (
        plan.SchemaVersion != 1 ||
        plan.Checkpoint != "gate-c2e-security-4663-one-shot-plan" ||
        plan.PrerequisiteCheckpoint !=
            "gate-c2d-security-4663-machine-readiness" ||
        plan.ServiceName != "WARRoomWindowsSensor" ||
        plan.ServiceIdentity != @"NT AUTHORITY\LocalService" ||
        plan.ProviderName != "Microsoft-Windows-Security-Auditing" ||
        plan.ChannelName != "Security" ||
        plan.EventId != 4663 ||
        plan.Level != 0 ||
        plan.ProfileId != "credential-store-read" ||
        plan.InertTargetPath !=
            @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\credential-store.fixture" ||
        plan.RequiredAccessMask != "0x00000001" ||
        !plan.RequiresFreshOperatorApproval ||
        !plan.RequiresC2dReadiness ||
        !plan.RequiresBaselineRecordId ||
        plan.MaximumTriggerWindowSeconds != 10 ||
        plan.MaximumQuerySeconds != 2 ||
        plan.MaximumEventsRead != 1 ||
        plan.MaximumNormalizedOutputBytes != 4096 ||
        !plan.RequiresRecordIdAfterBaseline ||
        !plan.RequiresEventTimeWithinTriggerWindow ||
        !plan.RequiresExactTargetHmacBinding ||
        plan.RetainsRawAccount ||
        plan.RetainsRawObjectPath ||
        plan.RetainsRawProcessPath ||
        plan.ChangesChannelAccess ||
        plan.ChangesAuditPolicy ||
        plan.ChangesTargetSacl ||
        plan.PlanReadsEvents ||
        plan.PlanEventsRead != 0 ||
        plan.RetryEnabled ||
        plan.PollingEnabled ||
        plan.RuntimeCollectionEnabled ||
        plan.TransportEnabled ||
        plan.InboundListenerEnabled ||
        plan.CommandChannelEnabled ||
        plan.ResponseActionEnabled ||
        WindowsEventSourceReadinessCommandParser.Parse(
            ["security-4663-one-shot-plan"]) !=
                WindowsEventSourceReadinessCommand.Security4663OneShotPlan)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_ONE_SHOT_PLAN_INVALID");
    }
}

static void RejectsSecurity4663OneShotPlanDrift()
{
    var plan = Security4663OneShotMachinePlan.BuildPlan();
    var driftedPlans = new[]
    {
        plan with { ProfileId = "unsecured-secret-read" },
        plan with { MaximumEventsRead = 2 },
        plan with { RequiresFreshOperatorApproval = false },
        plan with { RetainsRawObjectPath = true },
        plan with { PlanReadsEvents = true, PlanEventsRead = 1 },
        plan with { RetryEnabled = true },
        plan with { RuntimeCollectionEnabled = true },
        plan with { TransportEnabled = true },
        plan with { ResponseActionEnabled = true }
    };
    foreach (var drifted in driftedPlans)
    {
        ExpectInvalidData(
            () => Security4663OneShotMachinePlan.ValidatePlan(drifted),
            "SENSOR_C2E_SECURITY_4663_ONE_SHOT_PLAN_INVALID");
    }
}

static (Security4663ReadinessCheckResult Readiness,
    Security4663OneShotApproval Approval,
    DateTimeOffset Started,
    DateTimeOffset Completed,
    DateTimeOffset Now) Security4663OneShotInputs()
{
    var started = new DateTimeOffset(
        2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    return (
        Security4663ReadinessCheck.Check(
            FakeSecurity4663ReadinessProbe.Ready()),
        new Security4663OneShotApproval(
            true,
            Security4663OneShotMachinePlan.Checkpoint,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            42,
            started.AddSeconds(-30),
            started.AddMinutes(4)),
        started,
        started.AddSeconds(5),
        started.AddSeconds(6));
}

static InertWindowsSecurityEventRecord Security4663OneShotFixture(
    DateTimeOffset occurredAtUtc,
    long recordId)
{
    var fixture = InertSecurity4663Fixture();
    return fixture with
    {
        TimeCreatedUtc = occurredAtUtc,
        RecordId = recordId,
        EventData = new Dictionary<string, string>(
            fixture.EventData,
            StringComparer.Ordinal)
        {
            ["ObjectName"] =
                @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\credential-store.fixture"
        }
    };
}

static void ValidatesSecurity4663OneShotCoordinator()
{
    var inputs = Security4663OneShotInputs();
    var fixture = Security4663OneShotFixture(
        inputs.Started.AddSeconds(2),
        43);
    var reader = new FakeSecurity4663OneShotReader(
        new(Security4663OneShotReadState.Match, fixture));
    var coordinator = new Security4663OneShotCoordinator(reader);
    var key = InertClassificationKey();
    var result = coordinator.CollectOnce(
        inputs.Readiness,
        true,
        inputs.Approval,
        42,
        inputs.Started,
        inputs.Completed,
        inputs.Now,
        InertTargetBinding(
            fixture,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            key),
        InertProcessBinding(fixture, key),
        0,
        key,
        CancellationToken.None);
    if (
        result.SchemaVersion != 1 ||
        result.Checkpoint != Security4663OneShotMachinePlan.Checkpoint ||
        result.State != Security4663OneShotReadState.Match ||
        result.EventsRead != 1 ||
        result.RawEventContentRetained ||
        result.RuntimeWired ||
        result.NativeEventAccessEnabled ||
        result.RetryEnabled ||
        result.PollingEnabled ||
        result.TransportEnabled ||
        result.InboundListenerEnabled ||
        result.CommandChannelEnabled ||
        result.ResponseActionEnabled ||
        result.Classification is null ||
        !result.Classification.LocalClassificationComplete ||
        result.Classification.GenuineLiveEligible ||
        result.Classification.RawEventContentRetained ||
        reader.Calls != 1 ||
        reader.LastRequest is null ||
        reader.LastRequest.ProviderName !=
            "Microsoft-Windows-Security-Auditing" ||
        reader.LastRequest.ChannelName != "Security" ||
        reader.LastRequest.EventId != 4663 ||
        reader.LastRequest.Level != 0 ||
        reader.LastRequest.BaselineRecordId != 42 ||
        reader.LastRequest.MaximumQueryMilliseconds != 2_000 ||
        reader.LastRequest.MaximumEventsRead != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_COORDINATOR_INVALID");
    }
}

static void ValidatesSecurity4663OneShotNoMatch()
{
    var inputs = Security4663OneShotInputs();
    var reader = new FakeSecurity4663OneShotReader(
        new(Security4663OneShotReadState.NoMatch, null));
    var fixture = Security4663OneShotFixture(
        inputs.Started.AddSeconds(2),
        43);
    var key = InertClassificationKey();
    var result = new Security4663OneShotCoordinator(reader).CollectOnce(
        inputs.Readiness,
        true,
        inputs.Approval,
        42,
        inputs.Started,
        inputs.Completed,
        inputs.Now,
        InertTargetBinding(
            fixture,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            key),
        InertProcessBinding(fixture, key),
        0,
        key,
        CancellationToken.None);
    if (
        result.State != Security4663OneShotReadState.NoMatch ||
        result.EventsRead != 0 ||
        result.Classification is not null ||
        reader.Calls != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_NO_MATCH_INVALID");
    }
}

static void RejectsSecurity4663OneShotCoordinatorDrift()
{
    var inputs = Security4663OneShotInputs();
    var fixture = Security4663OneShotFixture(
        inputs.Started.AddSeconds(2),
        43);
    var key = InertClassificationKey();
    var blockedReader = new FakeSecurity4663OneShotReader(
        new(Security4663OneShotReadState.Match, fixture));
    ExpectInvalidData(
        () => new Security4663OneShotCoordinator(blockedReader).CollectOnce(
            inputs.Readiness,
            false,
            inputs.Approval,
            42,
            inputs.Started,
            inputs.Completed,
            inputs.Now,
            InertTargetBinding(
                fixture,
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
                key),
            InertProcessBinding(fixture, key),
            0,
            key,
            CancellationToken.None),
        "SENSOR_C2E_SECURITY_4663_READINESS_INVALID");
    if (blockedReader.Calls != 0)
    {
        throw new InvalidOperationException(
            "Security 4663 reader ran before prerequisite validation");
    }

    var reboundApprovalReader = new FakeSecurity4663OneShotReader(
        new(Security4663OneShotReadState.Match, fixture));
    ExpectInvalidData(
        () => new Security4663OneShotCoordinator(
            reboundApprovalReader).CollectOnce(
                inputs.Readiness,
                true,
                inputs.Approval with { BaselineRecordId = 41 },
                42,
                inputs.Started,
                inputs.Completed,
                inputs.Now,
                InertTargetBinding(
                    fixture,
                    InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
                    key),
                InertProcessBinding(fixture, key),
                0,
                key,
                CancellationToken.None),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_INVALID");
    if (reboundApprovalReader.Calls != 0)
    {
        throw new InvalidOperationException(
            "Security 4663 reader ran before approval binding validation");
    }

    var reboundTargetReader = new FakeSecurity4663OneShotReader(
        new(Security4663OneShotReadState.Match, fixture));
    ExpectInvalidData(
        () => new Security4663OneShotCoordinator(
            reboundTargetReader).CollectOnce(
                inputs.Readiness,
                true,
                inputs.Approval,
                42,
                inputs.Started,
                inputs.Completed,
                inputs.Now,
                InertTargetBinding(
                    InertSecurity4663Fixture(),
                    InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
                    key),
                InertProcessBinding(fixture, key),
                0,
                key,
                CancellationToken.None),
        "SENSOR_C2E_SECURITY_4663_TARGET_BINDING_INVALID");
    if (reboundTargetReader.Calls != 0)
    {
        throw new InvalidOperationException(
            "Security 4663 reader ran before target binding validation");
    }

    var rebound = fixture with { RecordId = 42 };
    var reboundReader = new FakeSecurity4663OneShotReader(
        new(Security4663OneShotReadState.Match, rebound));
    ExpectInvalidData(
        () => new Security4663OneShotCoordinator(reboundReader).CollectOnce(
            inputs.Readiness,
            true,
            inputs.Approval,
            42,
            inputs.Started,
            inputs.Completed,
            inputs.Now,
            InertTargetBinding(
                fixture,
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
                key),
            InertProcessBinding(fixture, key),
            0,
            key,
            CancellationToken.None),
        "SENSOR_C2E_SECURITY_4663_EVENT_BINDING_INVALID");

    var nonMatchReader = new FakeSecurity4663OneShotReader(
        new(Security4663OneShotReadState.NoMatch, fixture));
    ExpectInvalidData(
        () => new Security4663OneShotCoordinator(nonMatchReader).CollectOnce(
            inputs.Readiness,
            true,
            inputs.Approval,
            42,
            inputs.Started,
            inputs.Completed,
            inputs.Now,
            InertTargetBinding(
                fixture,
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
                key),
            InertProcessBinding(fixture, key),
            0,
            key,
            CancellationToken.None),
        "SENSOR_C2E_SECURITY_4663_NONMATCH_RECORD_INVALID");
}

static Security4663OneShotReadRequest Security4663OneShotRequest()
{
    var inputs = Security4663OneShotInputs();
    return new Security4663OneShotReadRequest(
        1,
        Security4663OneShotMachinePlan.Checkpoint,
        "Microsoft-Windows-Security-Auditing",
        "Security",
        4663,
        0,
        InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
        42,
        inputs.Started,
        inputs.Completed,
        2_000,
        1);
}

static string Security4663OneShotEventXml(
    InertWindowsSecurityEventRecord record)
{
    var fields = string.Concat(record.EventData.Select(field =>
        $"<Data Name=\"{System.Security.SecurityElement.Escape(field.Key)}\">" +
        $"{System.Security.SecurityElement.Escape(field.Value)}</Data>"));
    return
        "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">" +
        "<System>" +
        "<Provider Name=\"Microsoft-Windows-Security-Auditing\" " +
        "Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"/>" +
        $"<EventID>{record.EventId}</EventID>" +
        $"<Level>{record.Level}</Level>" +
        $"<TimeCreated SystemTime=\"{record.TimeCreatedUtc:O}\"/>" +
        $"<EventRecordID>{record.RecordId}</EventRecordID>" +
        $"<Channel>{record.ChannelName}</Channel>" +
        "</System>" +
        $"<EventData>{fields}</EventData>" +
        "</Event>";
}

static void ValidatesSecurity4663OneShotBoundedReader()
{
    var inputs = Security4663OneShotInputs();
    var fixture = Security4663OneShotFixture(
        inputs.Started.AddSeconds(2),
        43);
    var source = new FakeSecurity4663OneShotEventSource(
        new(
            Security4663OneShotReadState.Match,
            Security4663OneShotEventXml(fixture)));
    var result = new Security4663OneShotBoundedReader(source).ReadOne(
        Security4663OneShotRequest(),
        CancellationToken.None);
    if (
        result.State != Security4663OneShotReadState.Match ||
        result.Record is null ||
        result.Record.ProviderName != fixture.ProviderName ||
        result.Record.ChannelName != fixture.ChannelName ||
        result.Record.EventId != fixture.EventId ||
        result.Record.Level != fixture.Level ||
        result.Record.TimeCreatedUtc != fixture.TimeCreatedUtc ||
        result.Record.RecordId != fixture.RecordId ||
        !result.Record.EventData.SequenceEqual(fixture.EventData) ||
        source.Calls != 1 ||
        source.LastQuery is null ||
        source.LastQuery.LogName != "Security" ||
        source.LastQuery.XPath !=
            "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4663 and Level=0 and EventRecordID>42]]" ||
        !source.LastQuery.ReverseDirection ||
        source.LastQuery.TolerateQueryErrors ||
        source.LastQuery.MaximumEventsRead != 1 ||
        source.LastQuery.MaximumQueryMilliseconds != 2_000 ||
        source.LastQuery.MaximumEventXmlCharacters != 16_384 ||
        Security4663OneShotBoundedReader.RuntimeWired ||
        Security4663OneShotBoundedReader.NativeEventAccessEnabled)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_BOUNDED_READER_INVALID");
    }
}

static void ValidatesSecurity4663OneShotBoundedReaderFailures()
{
    foreach (var state in new[]
    {
        Security4663OneShotReadState.NoMatch,
        Security4663OneShotReadState.AccessDenied,
        Security4663OneShotReadState.SourceUnavailable,
        Security4663OneShotReadState.QueryFailed
    })
    {
        var source = new FakeSecurity4663OneShotEventSource(
            new(state, null));
        var result = new Security4663OneShotBoundedReader(source).ReadOne(
            Security4663OneShotRequest(),
            CancellationToken.None);
        if (
            result.State != state ||
            result.Record is not null ||
            source.Calls != 1)
        {
            throw new InvalidOperationException(
                "SENSOR_C2E_SECURITY_4663_SOURCE_FAILURE_INVALID");
        }
    }
}

static void RejectsSecurity4663OneShotBoundedReaderDrift()
{
    var inputs = Security4663OneShotInputs();
    var fixture = Security4663OneShotFixture(
        inputs.Started.AddSeconds(2),
        43);
    var source = new FakeSecurity4663OneShotEventSource(
        new(
            Security4663OneShotReadState.Match,
            Security4663OneShotEventXml(fixture)));
    ExpectInvalidData(
        () => new Security4663OneShotBoundedReader(source).ReadOne(
            Security4663OneShotRequest() with { MaximumEventsRead = 2 },
            CancellationToken.None),
        "SENSOR_C2E_SECURITY_4663_READ_REQUEST_INVALID");
    if (source.Calls != 0)
    {
        throw new InvalidOperationException(
            "Security 4663 source ran before request validation");
    }

    var xmlSource = new FakeSecurity4663OneShotEventSource(
        new(Security4663OneShotReadState.Match, "<!DOCTYPE Event><Event/>"));
    ExpectInvalidData(
        () => new Security4663OneShotBoundedReader(xmlSource).ReadOne(
            Security4663OneShotRequest(),
            CancellationToken.None),
        "SENSOR_C2E_SECURITY_4663_SOURCE_XML_INVALID");

    var nonMatchSource = new FakeSecurity4663OneShotEventSource(
        new(
            Security4663OneShotReadState.NoMatch,
            Security4663OneShotEventXml(fixture)));
    ExpectInvalidData(
        () => new Security4663OneShotBoundedReader(nonMatchSource).ReadOne(
            Security4663OneShotRequest(),
            CancellationToken.None),
        "SENSOR_C2E_SECURITY_4663_SOURCE_NONMATCH_XML_INVALID");
}

static Security4663OneShotSourceQuery Security4663NativeSourceQuery() =>
    new(
        "Security",
        Security4663OneShotBoundedReader.BuildXPath(42),
        true,
        false,
        1,
        2_000,
        Security4663OneShotBoundedReader.MaximumEventXmlCharacters);

static void ValidatesNativeSecurity4663OneShotSource()
{
    var inputs = Security4663OneShotInputs();
    var fixture = Security4663OneShotFixture(
        inputs.Started.AddSeconds(2),
        43);
    var session = new FakeSecurity4663EventLogSession(
        Security4663OneShotEventXml(fixture));
    var factory = new FakeSecurity4663EventLogSessionFactory(session);
    var result = new NativeSecurity4663OneShotEventSource(factory).ReadOne(
        Security4663NativeSourceQuery(),
        CancellationToken.None);
    if (
        result.State != Security4663OneShotReadState.Match ||
        result.EventXml != Security4663OneShotEventXml(fixture) ||
        factory.Calls != 1 ||
        factory.LastQuery != Security4663NativeSourceQuery() ||
        session.ReadCalls != 1 ||
        session.LastTimeout != TimeSpan.FromSeconds(2) ||
        !session.Disposed ||
        NativeSecurity4663OneShotEventSource.RuntimeWired ||
        NativeSecurity4663OneShotEventSource.ServiceRegistered)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_NATIVE_SOURCE_INVALID");
    }
}

static void ValidatesNativeSecurity4663OneShotNoMatch()
{
    var session = new FakeSecurity4663EventLogSession(null);
    var factory = new FakeSecurity4663EventLogSessionFactory(session);
    var result = new NativeSecurity4663OneShotEventSource(factory).ReadOne(
        Security4663NativeSourceQuery(),
        CancellationToken.None);
    if (
        result.State != Security4663OneShotReadState.NoMatch ||
        result.EventXml is not null ||
        session.ReadCalls != 1 ||
        !session.Disposed)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_NATIVE_NO_MATCH_INVALID");
    }
}

static void RejectsNativeSecurity4663OneShotSourceDrift()
{
    var session = new FakeSecurity4663EventLogSession(null);
    var factory = new FakeSecurity4663EventLogSessionFactory(session);
    ExpectInvalidData(
        () => new NativeSecurity4663OneShotEventSource(factory).ReadOne(
            Security4663NativeSourceQuery() with
            {
                XPath = "*[System[EventID=4663]]"
            },
            CancellationToken.None),
        "SENSOR_C2E_SECURITY_4663_NATIVE_QUERY_INVALID");
    if (factory.Calls != 0 || session.ReadCalls != 0)
    {
        throw new InvalidOperationException(
            "native Security 4663 source opened before query validation");
    }

    var deniedFactory = new FakeSecurity4663EventLogSessionFactory(
        new UnauthorizedAccessException());
    var denied = new NativeSecurity4663OneShotEventSource(
        deniedFactory).ReadOne(
            Security4663NativeSourceQuery(),
            CancellationToken.None);
    if (
        denied.State != Security4663OneShotReadState.AccessDenied ||
        denied.EventXml is not null ||
        deniedFactory.Calls != 1)
    {
        throw new InvalidOperationException(
            "native Security 4663 access denial failed open");
    }

    using var cancelled = new CancellationTokenSource();
    cancelled.Cancel();
    AssertThrows<OperationCanceledException>(
        () => new NativeSecurity4663OneShotEventSource(factory).ReadOne(
            Security4663NativeSourceQuery(),
            cancelled.Token));
    if (factory.Calls != 0)
    {
        throw new InvalidOperationException(
            "native Security 4663 source opened after cancellation");
    }
}

static void ValidatesSecurity4663OneShotBaseline()
{
    var source = new FakeSecurity4663LogMetadataSource(
        new(100, 50, false));
    var result = Security4663OneShotBaseline.Capture(source);
    if (
        result.SchemaVersion != 1 ||
        result.Checkpoint != Security4663OneShotMachinePlan.Checkpoint ||
        result.LogName != "Security" ||
        result.OldestRecordNumber != 100 ||
        result.RecordCount != 50 ||
        result.BaselineRecordId != 149 ||
        result.LogFull ||
        result.EventContentRead ||
        result.EventsRead != 0 ||
        result.RuntimeWired ||
        result.TransportEnabled ||
        result.InboundListenerEnabled ||
        result.CommandChannelEnabled ||
        result.ResponseActionEnabled ||
        source.Calls != 1 ||
        Security4663OneShotBaseline.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_BASELINE_INVALID");
    }
}

static void RejectsSecurity4663OneShotBaselineDrift()
{
    foreach (var metadata in new[]
    {
        new Security4663LogMetadata(null, 10, false),
        new Security4663LogMetadata(1, null, false),
        new Security4663LogMetadata(1, 0, false),
        new Security4663LogMetadata(
            Security4663OneShotCoordinator.MaximumJsonInteger,
            2,
            false),
        new Security4663LogMetadata(1, 1, null)
    })
    {
        ExpectInvalidData(
            () => Security4663OneShotBaseline.Capture(
                new FakeSecurity4663LogMetadataSource(metadata)),
            "SENSOR_C2E_SECURITY_4663_BASELINE_METADATA_INVALID");
    }
}

static void ValidatesNativeSecurity4663BaselineSource()
{
    var session = new FakeSecurity4663LogInformationSession(
        new(500, 25, true));
    var source = new NativeSecurity4663LogMetadataSource(session);
    var metadata = source.ReadSecurityLogMetadata();
    if (
        metadata != new Security4663LogMetadata(500, 25, true) ||
        session.Calls != 1 ||
        session.LastLogName != "Security" ||
        session.LastPathType !=
            System.Diagnostics.Eventing.Reader.PathType.LogName ||
        NativeSecurity4663LogMetadataSource.RuntimeWired ||
        NativeSecurity4663LogMetadataSource.ServiceRegistered)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_BASELINE_SOURCE_INVALID");
    }
}

static void ValidatesSecurity4663OneShotOperatorPlan()
{
    var plan = Security4663OneShotOperatorCeremony.BuildPlan();
    Security4663OneShotOperatorCeremony.ValidatePlan(plan);
    var expectedSteps = new[]
    {
        "validate-clean-installed-state",
        "apply-gate-c2d-readiness",
        "write-protected-expiring-approval",
        "capture-security-baseline-metadata",
        "start-localservice-once",
        "consume-approval-once",
        "trigger-fixed-inert-read",
        "read-at-most-one-post-baseline-event",
        "write-protected-normalized-result",
        "run-external-result-checker",
        "rollback-gate-c2d-always"
    };
    if (
        plan.SchemaVersion != 1 ||
        plan.Checkpoint != Security4663OneShotMachinePlan.Checkpoint ||
        plan.PrerequisiteCheckpoint !=
            "gate-c2d-security-4663-machine-readiness" ||
        plan.ServiceName != "WARRoomWindowsSensor" ||
        plan.ServiceIdentity != @"NT AUTHORITY\LocalService" ||
        plan.ServiceStartupArgument != "--security-4663-one-shot" ||
        plan.ApprovalPath !=
            @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-one-shot-approval.json" ||
        plan.ResultPath !=
            @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-one-shot-result.json" ||
        plan.FixedTargetPath !=
            @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\credential-store.fixture" ||
        plan.ProfileId != "credential-store-read" ||
        !plan.RequiresElevation ||
        !plan.RequiresOperatorPresence ||
        !plan.RequiresCleanCommit ||
        !plan.RequiresInstalledCommitMatch ||
        !plan.RequiresServiceStopped ||
        !plan.RequiresManualStart ||
        !plan.RequiresFreshMachineSignedApproval ||
        plan.MaximumApprovalLifetimeSeconds != 300 ||
        !plan.ConsumesApprovalOnce ||
        !plan.CapturesBaselineFromMetadataOnly ||
        !plan.GeneratesClassificationKeyInServiceMemory ||
        plan.PersistsClassificationKey ||
        !plan.TriggersOnlyFixedInertRead ||
        !plan.RequiresExternalCheckBeforeRollback ||
        !plan.RollbackAlwaysRequired ||
        plan.MaximumServiceStarts != 1 ||
        plan.MaximumTargets != 1 ||
        plan.MaximumEventsRead != 1 ||
        plan.RawEventRetentionAllowed ||
        plan.RetryEnabled ||
        plan.PollingEnabled ||
        plan.RuntimeCollectionEnabled ||
        plan.TransportEnabled ||
        plan.InboundListenerEnabled ||
        plan.CommandChannelEnabled ||
        plan.ResponseActionEnabled ||
        !plan.Steps.SequenceEqual(expectedSteps, StringComparer.Ordinal) ||
        Security4663OneShotOperatorCeremony.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_OPERATOR_PLAN_INVALID");
    }
}

static void RejectsSecurity4663OneShotOperatorPlanDrift()
{
    var plan = Security4663OneShotOperatorCeremony.BuildPlan();
    foreach (var drifted in new[]
    {
        plan with { RequiresOperatorPresence = false },
        plan with { RequiresFreshMachineSignedApproval = false },
        plan with { MaximumServiceStarts = 2 },
        plan with { MaximumEventsRead = 2 },
        plan with { PersistsClassificationKey = true },
        plan with { RetryEnabled = true },
        plan with { TransportEnabled = true },
        plan with { CommandChannelEnabled = true }
    })
    {
        ExpectInvalidData(
            () => Security4663OneShotOperatorCeremony.ValidatePlan(drifted),
            "SENSOR_C2E_SECURITY_4663_OPERATOR_PLAN_INVALID");
    }
}

static byte[] Security4663ApprovalNonce() =>
    Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();

static string Security4663ResultApprovalJson(
    ISensorIdentitySigner identity,
    string commit,
    DateTimeOffset now,
    long baselineRecordId = 42)
{
    var store = new FakeSecurity4663OneShotApprovalStore();
    _ = Security4663OneShotApprovalLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        baselineRecordId,
        now.UtcDateTime,
        Security4663ApprovalNonce());
    return store.Document ?? throw new InvalidOperationException(
        "approval fixture missing");
}

static void ValidatesSecurity4663OneShotApprovalLifecycle()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTime(2026, 8, 9, 10, 0, 0, DateTimeKind.Utc);
    using var identity = new FakeSensorIdentitySigner();
    var store = new FakeSecurity4663OneShotApprovalStore();
    var approval = Security4663OneShotApprovalLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        42,
        now,
        Security4663ApprovalNonce());
    if (
        approval.SchemaVersion != 1 ||
        approval.Profile !=
            Security4663OneShotApprovalLifecycle.Profile ||
        approval.State != "approved" ||
        approval.Checkpoint != Security4663OneShotMachinePlan.Checkpoint ||
        approval.ServiceName != "WARRoomWindowsSensor" ||
        approval.ServiceIdentity != @"NT AUTHORITY\LocalService" ||
        approval.ServiceStartupArgument != "--security-4663-one-shot" ||
        approval.TargetProfileId != "credential-store-read" ||
        approval.BaselineRecordId != 42 ||
        approval.InstalledCommit != commit ||
        approval.CertificateFingerprintSha256 !=
            identity.Descriptor.CertificateFingerprintSha256 ||
        approval.NonceBase64 != Convert.ToBase64String(
            Security4663ApprovalNonce()) ||
        approval.ApprovedAt != "2026-08-09T10:00:00.000Z" ||
        approval.ExpiresAt != "2026-08-09T10:05:00.000Z" ||
        Convert.FromBase64String(approval.SignatureBase64).Length != 64 ||
        store.WriteCount != 1 ||
        string.IsNullOrEmpty(store.Document))
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_APPROVAL_LIFECYCLE_INVALID");
    }

    var consumed = Security4663OneShotApprovalLifecycle.Consume(
        store,
        identity.Descriptor,
        commit,
        now.AddSeconds(30));
    if (
        !consumed.Approved ||
        consumed.Checkpoint != Security4663OneShotMachinePlan.Checkpoint ||
        consumed.Profile !=
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead ||
        consumed.BaselineRecordId != 42 ||
        consumed.ApprovedAtUtc != new DateTimeOffset(now) ||
        consumed.ExpiresAtUtc != new DateTimeOffset(now.AddMinutes(5)) ||
        store.ConsumeCount != 1 ||
        store.Document is not null ||
        !Security4663OneShotApprovalLifecycle.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_APPROVAL_CONSUME_INVALID");
    }
    ExpectInvalidData(
        () => Security4663OneShotApprovalLifecycle.Consume(
            store,
            identity.Descriptor,
            commit,
            now.AddMinutes(1)),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_MISSING");
}

static void RejectsSecurity4663OneShotApprovalDrift()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTime(2026, 8, 9, 10, 0, 0, DateTimeKind.Utc);
    using var identity = new FakeSensorIdentitySigner();
    var store = new FakeSecurity4663OneShotApprovalStore();
    _ = Security4663OneShotApprovalLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        42,
        now,
        Security4663ApprovalNonce());
    var json = store.Document ?? throw new InvalidOperationException(
        "approval fixture missing");
    ExpectInvalidData(
        () => Security4663OneShotApprovalLifecycle.ValidateApproval(
            json.Replace(
                "\"baselineRecordId\":42",
                "\"baselineRecordId\":43",
                StringComparison.Ordinal),
            identity.Descriptor,
            commit,
            now.AddMinutes(1)),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_INVALID");
    ExpectInvalidData(
        () => Security4663OneShotApprovalLifecycle.ValidateApproval(
            json,
            identity.Descriptor,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            now.AddMinutes(1)),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_INVALID");
    ExpectInvalidData(
        () => Security4663OneShotApprovalLifecycle.ValidateApproval(
            json,
            identity.Descriptor,
            commit,
            now.AddMinutes(5)),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_INVALID");
    ExpectInvalidData(
        () => Security4663OneShotApprovalLifecycle.ValidateApproval(
            json,
            identity.Descriptor,
            commit,
            now.AddMilliseconds(-1)),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_INVALID");
}

static void RejectsSecurity4663OneShotApprovalOverwrite()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTime(2026, 8, 9, 10, 0, 0, DateTimeKind.Utc);
    using var identity = new FakeSensorIdentitySigner();
    var existing = new FakeSecurity4663OneShotApprovalStore
    {
        Document = "existing"
    };
    ExpectInvalidData(
        () => Security4663OneShotApprovalLifecycle.CreateAndWrite(
            existing,
            identity,
            commit,
            42,
            now,
            Security4663ApprovalNonce()),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_ALREADY_EXISTS");
    if (existing.WriteCount != 0)
    {
        throw new InvalidOperationException("approval overwrite occurred");
    }

    using var corrupt = new FakeSensorIdentitySigner
    {
        CorruptSignature = true
    };
    var clean = new FakeSecurity4663OneShotApprovalStore();
    ExpectInvalidData(
        () => Security4663OneShotApprovalLifecycle.CreateAndWrite(
            clean,
            corrupt,
            commit,
            42,
            now,
            Security4663ApprovalNonce()),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_INVALID");
    if (clean.WriteCount != 0 || clean.Document is not null)
    {
        throw new InvalidOperationException(
            "invalid approval was persisted");
    }
}

static void ValidatesSecurity4663LiveOneShotApprovalLifecycle()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTime(2026, 8, 13, 10, 0, 0, DateTimeKind.Utc);
    var readiness = Security4663ReadinessCheck.Check(
        FakeSecurity4663ReadinessProbe.Ready());
    using var identity = new FakeSensorIdentitySigner();
    var store = new FakeSecurity4663LiveOneShotApprovalStore();
    var approval =
        Security4663LiveOneShotApprovalLifecycle.CreateAndWrite(
            store,
            identity,
            commit,
            readiness,
            42,
            now,
            Security4663ApprovalNonce());
    var json = store.Document ?? throw new InvalidOperationException(
        "live approval fixture missing");
    var validated = Security4663LiveOneShotApprovalLifecycle.ValidateApproval(
        json,
        identity.Descriptor,
        commit,
        now.AddSeconds(30));
    if (
        approval != validated ||
        approval.SchemaVersion != 1 ||
        approval.Profile !=
            Security4663LiveOneShotApprovalLifecycle.Profile ||
        approval.Checkpoint !=
            Security4663LiveOneShotApprovalLifecycle.Checkpoint ||
        approval.CapabilityPurpose !=
            Security4663LiveOneShotApprovalLifecycle.CapabilityPurpose ||
        approval.ReadinessCheckpoint !=
            Security4663ReadinessCeremony.Checkpoint ||
        approval.ServiceStartupArgument !=
            Security4663LiveOneShotApprovalLifecycle.StartupArgument ||
        approval.TargetProfileId !=
            Security4663LiveOneShotApprovalLifecycle.TargetProfileId ||
        approval.BaselineRecordId != 42 ||
        !approval.ReadinessVerified ||
        !approval.ChannelLocalServiceReadOnly ||
        !approval.AuditSuccessOnly ||
        !approval.TargetExists ||
        !approval.TargetZeroLength ||
        approval.TargetReparsePoint ||
        !approval.TargetSaclVerified ||
        approval.MaximumQueryMilliseconds != 2_000 ||
        approval.MaximumEventsRead != 1 ||
        approval.MaximumTriggerWindowSeconds != 10 ||
        !approval.NormalizedResultRequired ||
        approval.RawEventContentRetentionAllowed ||
        approval.RetryEnabled ||
        approval.PollingEnabled ||
        approval.RuntimeCollectionEnabled ||
        approval.TransportEnabled ||
        approval.InboundListenerEnabled ||
        approval.CommandChannelEnabled ||
        approval.ResponseActionEnabled ||
        approval.InstalledCommit != commit ||
        approval.ApprovedAt != "2026-08-13T10:00:00.000Z" ||
        approval.ExpiresAt != "2026-08-13T10:05:00.000Z" ||
        Convert.FromBase64String(approval.SignatureBase64).Length != 64 ||
        Encoding.UTF8.GetByteCount(json) >
            Security4663LiveOneShotApprovalLifecycle.MaximumDocumentBytes ||
        !Security4663LiveOneShotApprovalLifecycle.RuntimeWired ||
        store.ReadCount != 1 ||
        store.WriteCount != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_APPROVAL_LIFECYCLE_INVALID");
    }

    var consumed =
        Security4663LiveOneShotApprovalLifecycle.ConsumeEnvelope(
            store,
            identity.Descriptor,
            commit,
            now.AddSeconds(31));
    if (
        consumed.Approval != approval ||
        consumed.ExactJson != json ||
        consumed.EnvelopeSha256 !=
            Security4663LiveOneShotApprovalLifecycle.HashEnvelope(json) ||
        consumed.EnvelopeSha256.Length != 64 ||
        store.ConsumeCount != 1 ||
        store.Document is not null)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_APPROVAL_CONSUME_INVALID");
    }
}

static void RejectsSecurity4663LiveOneShotApprovalContextDrift()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTime(2026, 8, 13, 10, 0, 0, DateTimeKind.Utc);
    var readiness = Security4663ReadinessCheck.Check(
        FakeSecurity4663ReadinessProbe.Ready());
    var targetDrift = readiness with
    {
        Ready = false,
        Targets = Array.AsReadOnly(readiness.Targets.Select(target =>
            target.ProfileId ==
                Security4663LiveOneShotApprovalLifecycle.TargetProfileId
                ? target with { ZeroLength = false }
                : target).ToArray())
    };
    var driftedReadiness = new[]
    {
        readiness with { Ready = false },
        readiness with
        {
            Channel = readiness.Channel with
            {
                LocalServiceReadOnly = false,
                ErrorCode = "authority-drift"
            }
        },
        readiness with
        {
            AuditPolicy = readiness.AuditPolicy with
            {
                FailureEnabled = true
            }
        },
        readiness with { RuntimeCollectionEnabled = true },
        targetDrift
    };
    using var identity = new FakeSensorIdentitySigner();
    foreach (var drifted in driftedReadiness)
    {
        var store = new FakeSecurity4663LiveOneShotApprovalStore();
        ExpectInvalidData(
            () => Security4663LiveOneShotApprovalLifecycle.CreateAndWrite(
                store,
                identity,
                commit,
                drifted,
                42,
                now,
                Security4663ApprovalNonce()),
            "SENSOR_C2F_SECURITY_4663_APPROVAL_CONTEXT_INVALID");
        if (store.ReadCount != 0 || store.WriteCount != 0)
        {
            throw new InvalidOperationException(
                "live approval context performed store I/O");
        }
    }
}

static void RejectsSecurity4663LiveOneShotApprovalDrift()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTime(2026, 8, 13, 10, 0, 0, DateTimeKind.Utc);
    var readiness = Security4663ReadinessCheck.Check(
        FakeSecurity4663ReadinessProbe.Ready());
    using var identity = new FakeSensorIdentitySigner();
    var store = new FakeSecurity4663LiveOneShotApprovalStore();
    _ = Security4663LiveOneShotApprovalLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        readiness,
        42,
        now,
        Security4663ApprovalNonce());
    var json = store.Document ?? throw new InvalidOperationException(
        "live approval fixture missing");
    ExpectInvalidData(
        () => Security4663LiveOneShotApprovalLifecycle.ValidateApproval(
            json.Replace(
                "\"maximumEventsRead\":1",
                "\"maximumEventsRead\":2",
                StringComparison.Ordinal),
            identity.Descriptor,
            commit,
            now.AddSeconds(1)),
        "SENSOR_C2F_SECURITY_4663_APPROVAL_INVALID");
    ExpectInvalidData(
        () => Security4663LiveOneShotApprovalLifecycle.ValidateApproval(
            json,
            identity.Descriptor,
            commit,
            now.AddMinutes(5)),
        "SENSOR_C2F_SECURITY_4663_APPROVAL_INVALID");
    ExpectInvalidData(
        () => Security4663LiveOneShotApprovalLifecycle.ValidateApproval(
            json,
            identity.Descriptor,
            commit,
            now.AddMilliseconds(-1)),
        "SENSOR_C2F_SECURITY_4663_APPROVAL_INVALID");

    var oldJson = Security4663ResultApprovalJson(identity, commit,
        new DateTimeOffset(now));
    ExpectInvalidData(
        () => Security4663LiveOneShotApprovalLifecycle.ValidateApproval(
            oldJson,
            identity.Descriptor,
            commit,
            now.AddSeconds(1)),
        "SENSOR_C2F_SECURITY_4663_APPROVAL_FIELDS_INVALID");
    ExpectInvalidData(
        () => Security4663OneShotApprovalLifecycle.ValidateApproval(
            json,
            identity.Descriptor,
            commit,
            now.AddSeconds(1)),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_FIELDS_INVALID");

    var existing = new FakeSecurity4663LiveOneShotApprovalStore
    {
        Document = "existing"
    };
    ExpectInvalidData(
        () => Security4663LiveOneShotApprovalLifecycle.CreateAndWrite(
            existing,
            identity,
            commit,
            readiness,
            42,
            now,
            Security4663ApprovalNonce()),
        "SENSOR_C2F_SECURITY_4663_APPROVAL_ALREADY_EXISTS");
    if (existing.WriteCount != 0)
    {
        throw new InvalidOperationException("live approval overwrite occurred");
    }

    using var corrupt = new FakeSensorIdentitySigner
    {
        CorruptSignature = true
    };
    var clean = new FakeSecurity4663LiveOneShotApprovalStore();
    ExpectInvalidData(
        () => Security4663LiveOneShotApprovalLifecycle.CreateAndWrite(
            clean,
            corrupt,
            commit,
            readiness,
            42,
            now,
            Security4663ApprovalNonce()),
        "SENSOR_C2F_SECURITY_4663_APPROVAL_INVALID");
    if (clean.WriteCount != 0 || clean.Document is not null)
    {
        throw new InvalidOperationException(
            "invalid live approval was persisted");
    }
}

static void ValidatesSecurity4663LiveOneShotApprovalFileStore()
{
    var plan = Security4663LiveOneShotApprovalFilePolicy.BuildPlan();
    Security4663LiveOneShotApprovalFilePolicy.ValidatePlan(plan);
    if (
        plan.SchemaVersion != 1 ||
        plan.Checkpoint !=
            Security4663LiveOneShotApprovalLifecycle.Checkpoint ||
        plan.ApprovalPath !=
            NativeSecurity4663LiveOneShotApprovalFileStore.ApprovalPath ||
        !plan.ApprovalPath.EndsWith(
            "security-4663-live-one-shot-approval.json",
            StringComparison.Ordinal) ||
        plan.MaximumDocumentBytes != 4_096 ||
        plan.OwnerSid != "S-1-5-32-544" ||
        plan.ServiceSid != "S-1-5-19" ||
        plan.ServiceRightsMask != 0x00130089 ||
        !plan.RequiresProtectedDacl ||
        !plan.RequiresCreateNew ||
        !plan.RejectsReparsePoints ||
        !plan.RejectsHardLinks ||
        !plan.UsesExclusiveConsumeHandle ||
        !plan.UsesHandleDispositionDelete ||
        plan.ServiceConsumeReadsParentAcl ||
        plan.AllowsOverwrite ||
        plan.AllowsServiceWrite ||
        plan.RetryEnabled ||
        plan.PollingEnabled ||
        plan.TransportEnabled ||
        plan.CommandChannelEnabled ||
        plan.RuntimeWired ||
        !NativeSecurity4663LiveOneShotApprovalFileStore.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_APPROVAL_FILE_PLAN_INVALID");
    }
    var acl = Security4663LiveOneShotApprovalFilePolicy.Snapshot(
        Security4663LiveOneShotApprovalFilePolicy.CreateFileSecurity());
    Security4663LiveOneShotApprovalFilePolicy.ValidateFileAcl(acl);
    var serviceRule = acl.Rules.Single(rule => rule.Sid == "S-1-5-19");
    if (
        serviceRule.RightsMask != 0x00130089 ||
        acl.Rules.Any(rule => rule.IsInherited ||
            rule.Inheritance != InheritanceFlags.None ||
            rule.Propagation != PropagationFlags.None))
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_APPROVAL_FILE_ACL_INVALID");
    }
}

static void RejectsSecurity4663LiveOneShotApprovalFileStoreDrift()
{
    var plan = Security4663LiveOneShotApprovalFilePolicy.BuildPlan();
    foreach (var drifted in new[]
    {
        plan with { ApprovalPath = plan.ApprovalPath + ".alternate" },
        plan with { RejectsHardLinks = false },
        plan with { ServiceRightsMask = 0x0013019F },
        plan with { ServiceConsumeReadsParentAcl = true },
        plan with { AllowsServiceWrite = true },
        plan with { RuntimeWired = true }
    })
    {
        ExpectInvalidData(
            () => Security4663LiveOneShotApprovalFilePolicy.ValidatePlan(
                drifted),
            "SENSOR_C2F_SECURITY_4663_APPROVAL_FILE_PLAN_INVALID");
    }

    var acl = Security4663LiveOneShotApprovalFilePolicy.Snapshot(
        Security4663LiveOneShotApprovalFilePolicy.CreateFileSecurity());
    var serviceRule = acl.Rules.Single(rule => rule.Sid == "S-1-5-19");
    foreach (var drifted in new[]
    {
        acl with { OwnerSid = "S-1-5-18" },
        acl with { IsProtected = false },
        acl with
        {
            Rules = acl.Rules.Select(rule => rule == serviceRule
                ? rule with { RightsMask = 0x0013019F }
                : rule).ToArray()
        },
        acl with
        {
            Rules = acl.Rules.Append(serviceRule with
            {
                Sid = "S-1-5-11"
            }).ToArray()
        }
    })
    {
        ExpectInvalidData(
            () => Security4663LiveOneShotApprovalFilePolicy.ValidateFileAcl(
                drifted),
            "SENSOR_C2F_SECURITY_4663_APPROVAL_FILE_ACL_INVALID");
    }

    Security4663LiveOneShotApprovalFilePolicy.ValidateNativeState(
        new(false, false, false, 1, 1),
        allowEmpty: false);
    Security4663LiveOneShotApprovalFilePolicy.ValidateNativeState(
        new(false, false, false, 1, 0),
        allowEmpty: true);
    foreach (var state in new[]
    {
        new Security4663LiveApprovalFileNativeState(true, false, false, 1, 1),
        new Security4663LiveApprovalFileNativeState(false, true, false, 1, 1),
        new Security4663LiveApprovalFileNativeState(false, false, true, 1, 1),
        new Security4663LiveApprovalFileNativeState(false, false, false, 2, 1),
        new Security4663LiveApprovalFileNativeState(false, false, false, 1, 4_097)
    })
    {
        ExpectInvalidData(
            () => Security4663LiveOneShotApprovalFilePolicy.ValidateNativeState(
                state,
                allowEmpty: false),
            "SENSOR_C2F_SECURITY_4663_APPROVAL_FILE_STATE_INVALID");
    }
}

static void ValidatesSecurity4663LiveOneShotApprovalOperatorPlan()
{
    var plan = Security4663LiveOneShotApprovalOperator.BuildPlan();
    Security4663LiveOneShotApprovalOperator.ValidatePlan(plan);
    var commands = new[] { "plan", "write", "check", "absent-check", "cleanup" };
    if (
        plan.SchemaVersion != 1 ||
        plan.Checkpoint != Security4663LiveOneShotApprovalLifecycle.Checkpoint ||
        !plan.Commands.SequenceEqual(commands, StringComparer.Ordinal) ||
        plan.ApprovalPath !=
            NativeSecurity4663LiveOneShotApprovalFileStore.ApprovalPath ||
        !plan.RequiresAdministratorForMutation ||
        !plan.RequiresAdministratorForProtectedRead ||
        !plan.DerivesInstalledCommitFromProtectedManifest ||
        !plan.DerivesIdentityFromMachineKey ||
        plan.ExternalCheckerHasSigningAuthority ||
        !plan.VerifiesExactC2dReadiness ||
        !plan.CapturesBaselineFromMetadataOnly ||
        plan.AcceptsCallerInput ||
        plan.ReadsEvents ||
        plan.MaximumEventsRead != 0 ||
        plan.StartsService ||
        plan.MutatesService ||
        plan.CleanupRequiresIdentityOrManifest ||
        !plan.CleanupUsesOnlyFixedApprovalPath ||
        plan.RetryEnabled ||
        plan.PollingEnabled ||
        plan.TransportEnabled ||
        plan.InboundListenerEnabled ||
        plan.CommandChannelEnabled ||
        plan.ResponseActionEnabled ||
        plan.RuntimeWired ||
        Security4663LiveOneShotApprovalOperator.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_PLAN_INVALID");
    }
    for (var index = 0; index < commands.Length; index++)
    {
        if (Security4663LiveOneShotApprovalOperatorCommandParser.Parse(
            [commands[index]]) !=
            (Security4663LiveOneShotApprovalOperatorCommand)index)
        {
            throw new InvalidOperationException(
                "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_COMMAND_INVALID");
        }
    }
    ExpectInvalidData(
        () => Security4663LiveOneShotApprovalOperatorCommandParser.Parse(
            ["consume"]),
        "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_COMMAND_INVALID");
    ExpectInvalidData(
        () => Security4663LiveOneShotApprovalOperator.ValidatePlan(
            plan with { RuntimeWired = true }),
        "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_PLAN_INVALID");
}

static void ValidatesSecurity4663LiveOneShotApprovalOperatorWorkflow()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTime(2026, 8, 13, 12, 0, 0, DateTimeKind.Utc);
    using var identity = new FakeSensorIdentitySigner();
    var manifest = new InstallManifestBinding(
        commit,
        identity.Descriptor.CertificateFingerprintSha256,
        new string('b', 64));
    var store = new FakeSecurity4663LiveOneShotApprovalStore();
    var readiness = FakeSecurity4663ReadinessProbe.Ready();
    var source = new FakeSecurity4663LogMetadataSource(
        new Security4663LogMetadata(100, 5, false));
    var written = Security4663LiveOneShotApprovalOperator.Write(
        store, identity, manifest, readiness, source, now,
        Security4663ApprovalNonce());
    var checkedApproval = Security4663LiveOneShotApprovalOperator.Check(
        store, identity.Descriptor, manifest, now.AddSeconds(10));
    var cleaned = Security4663LiveOneShotApprovalOperator.Cleanup(store);
    var absent = Security4663LiveOneShotApprovalOperator.CheckAbsent(store);
    if (
        source.Calls != 1 ||
        readiness.ChannelCalls != 1 ||
        readiness.AuditPolicyCalls != 1 ||
        written.State != "approved" ||
        written.BaselineRecordId != 104 ||
        !written.ReadinessVerified ||
        !written.ApprovalPresent ||
        checkedApproval.State != "valid" ||
        !checkedApproval.ApprovalPresent ||
        cleaned.State != "removed" ||
        !cleaned.RecoveryRemoved ||
        cleaned.InstalledCommit is not null ||
        cleaned.IdentityFingerprintSha256 is not null ||
        absent.State != "absent" ||
        absent.ApprovalPresent ||
        store.CleanupCount != 1 ||
        store.AbsentCheckCount != 1 ||
        store.ConsumeCount != 0 ||
        store.Document is not null ||
        new[] { written, checkedApproval, cleaned, absent }.Any(value =>
            value.EventContentRead || value.EventsRead != 0 ||
            value.ServiceStarted || value.ServiceMutated ||
            value.RetryEnabled || value.PollingEnabled ||
            value.TransportEnabled || value.InboundListenerEnabled ||
            value.CommandChannelEnabled || value.ResponseActionEnabled ||
            value.RuntimeWired))
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_WORKFLOW_INVALID");
    }

    var blockedStore = new FakeSecurity4663LiveOneShotApprovalStore();
    var blockedSource = new FakeSecurity4663LogMetadataSource(
        new Security4663LogMetadata(100, 5, false));
    var blockedReadiness = FakeSecurity4663ReadinessProbe.Ready() with
    {
        Channel = new(false, false, "blocked")
    };
    ExpectInvalidData(
        () => Security4663LiveOneShotApprovalOperator.Write(
            blockedStore, identity, manifest, blockedReadiness, blockedSource,
            now, Security4663ApprovalNonce()),
        "SENSOR_C2F_SECURITY_4663_APPROVAL_OPERATOR_SOURCE_INVALID");
    if (blockedSource.Calls != 0 || blockedStore.WriteCount != 0)
    {
        throw new InvalidOperationException(
            "blocked live approval reached metadata or persistence");
    }
}

static void ValidatesSecurity4663LiveOneShotApprovalIndependentCleanup()
{
    var absentStore = new FakeSecurity4663LiveOneShotApprovalStore();
    var absent = Security4663LiveOneShotApprovalOperator.Cleanup(absentStore);
    var partialStore = new FakeSecurity4663LiveOneShotApprovalStore
    {
        Document = "{partial"
    };
    var removed = Security4663LiveOneShotApprovalOperator.Cleanup(partialStore);
    if (
        absent.State != "absent" || absent.RecoveryRemoved ||
        absent.InstalledCommit is not null ||
        absent.IdentityFingerprintSha256 is not null ||
        removed.State != "removed" || !removed.RecoveryRemoved ||
        removed.InstalledCommit is not null ||
        removed.IdentityFingerprintSha256 is not null ||
        partialStore.Document is not null)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_APPROVAL_INDEPENDENT_CLEANUP_INVALID");
    }

    var finalAcl = Security4663LiveOneShotApprovalFilePolicy.Snapshot(
        Security4663LiveOneShotApprovalFilePolicy.CreateFileSecurity());
    var recoveryAcl = finalAcl with
    {
        IsProtected = false,
        Rules = finalAcl.Rules.Where(rule => rule.Sid != "S-1-5-19")
            .Select(rule => rule with { IsInherited = true }).ToArray()
    };
    Security4663LiveOneShotApprovalFilePolicy.ValidateRecoveryFileAcl(
        recoveryAcl);
    ExpectInvalidData(
        () => Security4663LiveOneShotApprovalFilePolicy
            .ValidateRecoveryFileAcl(recoveryAcl with
            {
                Rules = recoveryAcl.Rules.Append(new(
                    "S-1-5-19", 1, false, AccessControlType.Allow,
                    InheritanceFlags.None, PropagationFlags.None)).ToArray()
            }),
        "SENSOR_C2F_SECURITY_4663_APPROVAL_FILE_ACL_INVALID");
}

static ConsumedSecurity4663LiveOneShotApproval
    Security4663LiveConsumedApproval(
        ISensorIdentitySigner identity,
        string commit,
        DateTimeOffset approvedAt,
        long baselineRecordId = 42)
{
    var readiness = Security4663ReadinessCheck.Check(
        FakeSecurity4663ReadinessProbe.Ready());
    var store = new FakeSecurity4663LiveOneShotApprovalStore();
    _ = Security4663LiveOneShotApprovalLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        readiness,
        baselineRecordId,
        approvedAt.UtcDateTime,
        Security4663ApprovalNonce());
    return Security4663LiveOneShotApprovalLifecycle.ConsumeEnvelope(
        store,
        identity.Descriptor,
        commit,
        approvedAt.AddSeconds(1).UtcDateTime);
}

static Security4663LiveOneShotNormalizedSourceResult
    Security4663LiveNoMatchResult() =>
        new(
            1,
            Security4663LiveOneShotResultLifecycle.Checkpoint,
            Security4663OneShotReadState.NoMatch,
            0,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            null);

static Security4663LiveOneShotNormalizedSourceResult
    Security4663LiveMatchResult()
{
    var old = Security4663MatchResult();
    return new(
        1,
        Security4663LiveOneShotResultLifecycle.Checkpoint,
        old.State,
        old.EventsRead,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        old.Classification);
}

static void ValidatesSecurity4663LiveOneShotResultLifecycle()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    using var identity = new FakeSensorIdentitySigner();
    var approval = Security4663LiveConsumedApproval(
        identity,
        commit,
        now.AddSeconds(-1));
    var store = new FakeSecurity4663LiveOneShotResultStore();
    var result = Security4663LiveOneShotResultLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        approval,
        now,
        now.AddSeconds(1),
        Security4663LiveNoMatchResult(),
        now.AddSeconds(2));
    var validated = Security4663LiveOneShotResultLifecycle.ReadAndValidate(
        store,
        identity.Descriptor,
        commit,
        now.AddSeconds(2));
    if (
        result != validated ||
        result.SchemaVersion != 1 ||
        result.Profile != Security4663LiveOneShotResultLifecycle.Profile ||
        result.Checkpoint !=
            Security4663LiveOneShotApprovalLifecycle.Checkpoint ||
        result.TargetProfileId !=
            Security4663LiveOneShotApprovalLifecycle.TargetProfileId ||
        result.ReadState != "no-match" ||
        result.EventsRead != 0 ||
        result.Provider is not null ||
        result.Channel is not null ||
        result.EventFamily is not null ||
        result.OccurredAt is not null ||
        result.SourceRecordTagHmacSha256 is not null ||
        result.ActorTrust is not null ||
        result.Action is not null ||
        result.SubjectClass is not null ||
        result.ObjectClass is not null ||
        result.Outcome is not null ||
        result.BaselineState is not null ||
        result.VisibilityState is not null ||
        result.TargetSaclVerified is not null ||
        result.LocalClassificationComplete is not null ||
        result.GenuineLiveEligible ||
        result.RawEventContentRetained ||
        result.RuntimeCollectionEnabled ||
        result.RetryEnabled ||
        result.PollingEnabled ||
        result.TransportEnabled ||
        result.InboundListenerEnabled ||
        result.CommandChannelEnabled ||
        result.ResponseActionEnabled ||
        result.TriggerStartedAt != "2026-08-09T10:00:00.000Z" ||
        result.TriggerCompletedAt != "2026-08-09T10:00:01.000Z" ||
        result.CreatedAt != "2026-08-09T10:00:02.000Z" ||
        result.InstalledCommit != commit ||
        result.ApprovalEnvelopeSha256 != approval.EnvelopeSha256 ||
        Convert.FromBase64String(result.SignatureBase64).Length != 64 ||
        store.ReadCount != 2 ||
        store.WriteCount != 1 ||
        string.IsNullOrEmpty(store.Document) ||
        Encoding.UTF8.GetByteCount(store.Document) > 4_096 ||
        !Security4663LiveOneShotResultLifecycle.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_RESULT_LIFECYCLE_INVALID");
    }
}

static void ValidatesSecurity4663LiveOneShotMatchResult()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    using var identity = new FakeSensorIdentitySigner();
    var approval = Security4663LiveConsumedApproval(
        identity,
        commit,
        now.AddSeconds(-1));
    var source = Security4663LiveMatchResult();
    var firstStore = new FakeSecurity4663LiveOneShotResultStore();
    var first = Security4663LiveOneShotResultLifecycle.CreateAndWrite(
        firstStore,
        identity,
        commit,
        approval,
        now,
        now.AddSeconds(1),
        source,
        now.AddSeconds(2));
    var secondStore = new FakeSecurity4663LiveOneShotResultStore();
    var second = Security4663LiveOneShotResultLifecycle.CreateAndWrite(
        secondStore,
        identity,
        commit,
        approval,
        now,
        now.AddSeconds(1),
        source,
        now.AddSeconds(2));
    var json = firstStore.Document ?? string.Empty;
    if (
        first.ReadState != "match" ||
        first.EventsRead != 1 ||
        first.Provider != "windows-security" ||
        first.Channel != "security" ||
        first.EventFamily != "file-access" ||
        first.OccurredAt != "2026-08-09T10:00:00.000Z" ||
        first.SourceRecordTagHmacSha256 is null ||
        first.SourceRecordTagHmacSha256.Length != 64 ||
        first.SourceRecordTagHmacSha256 ==
            second.SourceRecordTagHmacSha256 ||
        first.ActorTrust != "untrusted" ||
        first.Action != "read" ||
        first.SubjectClass != "other" ||
        first.ObjectClass != "credential-store" ||
        first.Outcome != "success" ||
        first.BaselineState != "rare" ||
        first.VisibilityState != "unknown" ||
        first.TargetSaclVerified != true ||
        first.LocalClassificationComplete != true ||
        first.GenuineLiveEligible ||
        first.RawEventContentRetained ||
        json.Contains("SubjectUser", StringComparison.Ordinal) ||
        json.Contains("ObjectName", StringComparison.Ordinal) ||
        json.Contains("ProcessName", StringComparison.Ordinal) ||
        json.Contains("EventXml", StringComparison.Ordinal) ||
        json.Contains("baselineRecordId", StringComparison.Ordinal) ||
        json.Contains("sourceRecordId", StringComparison.Ordinal))
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_RESULT_RAW_RETENTION_INVALID");
    }
    ExpectInvalidData(
        () => Security4663OneShotResultLifecycle.Validate(
            json,
            identity.Descriptor,
            commit,
            now.AddSeconds(2)),
        "SENSOR_C2E_SECURITY_4663_RESULT_INVALID");
}

static void RejectsSecurity4663LiveOneShotResultDrift()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    using var identity = new FakeSensorIdentitySigner();
    var approval = Security4663LiveConsumedApproval(
        identity,
        commit,
        now.AddSeconds(-1));
    var store = new FakeSecurity4663LiveOneShotResultStore();
    _ = Security4663LiveOneShotResultLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        approval,
        now,
        now.AddSeconds(1),
        Security4663LiveNoMatchResult(),
        now.AddSeconds(2));
    var json = store.Document ?? throw new InvalidOperationException(
        "live result fixture missing");
    ExpectInvalidData(
        () => Security4663LiveOneShotResultLifecycle.Validate(
            json.Replace(
                "\"transportEnabled\":false",
                "\"transportEnabled\":true",
                StringComparison.Ordinal),
            identity.Descriptor,
            commit,
            now.AddSeconds(2)),
        "SENSOR_C2F_SECURITY_4663_RESULT_INVALID");
    ExpectInvalidData(
        () => Security4663LiveOneShotResultLifecycle.Validate(
            json,
            identity.Descriptor,
            commit,
            now.AddMinutes(6)),
        "SENSOR_C2F_SECURITY_4663_RESULT_INVALID");
    ExpectInvalidData(
        () => Security4663LiveOneShotResultLifecycle.CreateAndWrite(
            store,
            identity,
            commit,
            approval,
            now,
            now.AddSeconds(1),
            Security4663LiveNoMatchResult(),
            now.AddSeconds(2)),
        "SENSOR_C2F_SECURITY_4663_RESULT_ALREADY_EXISTS");

    var clean = new FakeSecurity4663LiveOneShotResultStore();
    ExpectInvalidData(
        () => Security4663LiveOneShotResultLifecycle.CreateAndWrite(
            clean,
            identity,
            commit,
            approval,
            now,
            now.AddSeconds(1),
            Security4663LiveNoMatchResult() with
            {
                Checkpoint = Security4663OneShotMachinePlan.Checkpoint
            },
            now.AddSeconds(2)),
        "SENSOR_C2F_SECURITY_4663_RESULT_CONTEXT_INVALID");
    ExpectInvalidData(
        () => Security4663LiveOneShotResultLifecycle.CreateAndWrite(
            clean,
            identity,
            commit,
            approval,
            now,
            now.AddSeconds(1),
            Security4663LiveNoMatchResult(),
            now.AddSeconds(7)),
        "SENSOR_C2F_SECURITY_4663_RESULT_CONTEXT_INVALID");
    ExpectInvalidData(
        () => Security4663LiveOneShotResultLifecycle.CreateAndWrite(
            clean,
            identity,
            commit,
            approval,
            now,
            now.AddSeconds(1),
            Security4663LiveNoMatchResult() with { EventsRead = 2 },
            now.AddSeconds(2)),
        "SENSOR_C2F_SECURITY_4663_RESULT_CONTEXT_INVALID");
    ExpectInvalidData(
        () => Security4663LiveOneShotResultLifecycle.CreateAndWrite(
            clean,
            identity,
            commit,
            approval,
            now,
            now.AddSeconds(1),
            Security4663LiveNoMatchResult() with { TransportEnabled = true },
            now.AddSeconds(2)),
        "SENSOR_C2F_SECURITY_4663_RESULT_CONTEXT_INVALID");
    var forged = approval with
    {
        EnvelopeSha256 = new string('b', 64)
    };
    ExpectInvalidData(
        () => Security4663LiveOneShotResultLifecycle.CreateAndWrite(
            clean,
            identity,
            commit,
            forged,
            now,
            now.AddSeconds(1),
            Security4663LiveNoMatchResult(),
            now.AddSeconds(2)),
        "SENSOR_C2F_SECURITY_4663_RESULT_APPROVAL_INVALID");
    if (clean.WriteCount != 0 || clean.ReadCount != 0)
    {
        throw new InvalidOperationException(
            "invalid live result reached persistence");
    }

    using var corrupt = new FakeSensorIdentitySigner();
    var corruptApproval = Security4663LiveConsumedApproval(
        corrupt,
        commit,
        now.AddSeconds(-1));
    corrupt.CorruptSignature = true;
    ExpectInvalidData(
        () => Security4663LiveOneShotResultLifecycle.CreateAndWrite(
            clean,
            corrupt,
            commit,
            corruptApproval,
            now,
            now.AddSeconds(1),
            Security4663LiveNoMatchResult(),
            now.AddSeconds(2)),
        "SENSOR_C2F_SECURITY_4663_RESULT_INVALID");
    if (clean.WriteCount != 0 || clean.Document is not null)
    {
        throw new InvalidOperationException(
            "corrupt live result was persisted");
    }
}

static void ValidatesSecurity4663LiveOneShotResultFileSlot()
{
    var plan = Security4663LiveOneShotResultFilePolicy.BuildPlan();
    Security4663LiveOneShotResultFilePolicy.ValidatePlan(plan);
    if (
        plan.SchemaVersion != 1 ||
        plan.Checkpoint != Security4663LiveOneShotResultLifecycle.Checkpoint ||
        plan.ResultPath != NativeSecurity4663LiveOneShotResultFileSlot.ResultPath ||
        plan.MaximumDocumentBytes != 4_096 ||
        plan.OwnerSid != "S-1-5-32-544" ||
        !plan.FullControlSids.SequenceEqual(
            new[] { "S-1-5-18", "S-1-5-32-544" }, StringComparer.Ordinal) ||
        plan.ServiceSid != "S-1-5-19" ||
        plan.ServiceRightsMask != 0x00100082 ||
        !plan.RequiresAdministratorToCreate ||
        !plan.RequiresPrecreatedEmptyFile || !plan.RequiresProtectedDacl ||
        !plan.RejectsInheritedRules || !plan.RejectsReparsePoints ||
        !plan.RejectsHardLinks || !plan.RejectsStaleContent ||
        !plan.UsesOpenExisting || !plan.UsesOneExclusiveWriteThroughHandle ||
        plan.ServiceCallsFlushFileBuffers ||
        plan.AllowsOverwrite || plan.AllowsServiceRead ||
        !plan.AllowsServiceAttributeRead ||
        plan.AllowsServiceCreate || plan.AllowsServiceDelete ||
        plan.AllowsServiceAclChange || plan.AllowsServiceDirectoryAccess ||
        plan.RetryEnabled || plan.PollingEnabled || plan.TransportEnabled ||
        plan.CommandChannelEnabled || plan.RuntimeWired ||
        NativeSecurity4663LiveOneShotResultFileSlot.RuntimeWired ||
        !NativeSecurity4663LiveOneShotResultFileStore.RuntimeWired ||
        !NativeSecurity4663LiveOneShotResultFileStore.ServiceRegistered)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_PLAN_INVALID");
    }

    var acl = Security4663LiveOneShotResultFilePolicy.Snapshot(
        Security4663LiveOneShotResultFilePolicy.CreateFileSecurity());
    Security4663LiveOneShotResultFilePolicy.ValidateFileAcl(acl);
    var serviceRule = acl.Rules.Single(rule => rule.Sid == "S-1-5-19");
    if (serviceRule.RightsMask != 0x00100082 || acl.Rules.Any(rule =>
        rule.IsInherited || rule.Inheritance != InheritanceFlags.None ||
        rule.Propagation != PropagationFlags.None))
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ACL_INVALID");
    }
    if (new NativeSecurity4663LiveOneShotResultFileStore().ReadExisting() is not null)
    {
        throw new InvalidOperationException("live result writer read unexpectedly");
    }
}

static void RejectsSecurity4663LiveOneShotResultFileSlotDrift()
{
    var plan = Security4663LiveOneShotResultFilePolicy.BuildPlan();
    foreach (var drifted in new[]
    {
        plan with { ResultPath = plan.ResultPath + ".alternate" },
        plan with { ServiceRightsMask = 0x82 },
        plan with { UsesOpenExisting = false },
        plan with { ServiceCallsFlushFileBuffers = true },
        plan with { AllowsServiceAttributeRead = false },
        plan with { RejectsHardLinks = false },
        plan with { AllowsServiceRead = true },
        plan with { AllowsServiceCreate = true },
        plan with { AllowsServiceDelete = true },
        plan with { TransportEnabled = true },
        plan with { FullControlSids = new[] { "S-1-5-18" } }
    })
    {
        ExpectInvalidData(
            () => Security4663LiveOneShotResultFilePolicy.ValidatePlan(drifted),
            "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_PLAN_INVALID");
    }

    var acl = Security4663LiveOneShotResultFilePolicy.Snapshot(
        Security4663LiveOneShotResultFilePolicy.CreateFileSecurity());
    var service = acl.Rules.Single(rule => rule.Sid == "S-1-5-19");
    foreach (var drifted in new[]
    {
        acl with { OwnerSid = "S-1-5-18" },
        acl with { IsProtected = false },
        acl with { Rules = acl.Rules.Select(rule => rule == service
            ? rule with { RightsMask = 0x82 } : rule).ToArray() },
        acl with { Rules = acl.Rules.Append(service with
            { Sid = "S-1-5-11" }).ToArray() }
    })
    {
        ExpectInvalidData(
            () => Security4663LiveOneShotResultFilePolicy.ValidateFileAcl(drifted),
            "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ACL_INVALID");
    }
}

static void RejectsSecurity4663LiveOneShotResultNativeStateDrift()
{
    Security4663LiveOneShotResultFilePolicy.ValidateNativeFileState(
        new(0x80, 0, 1, false, false), true);
    Security4663LiveOneShotResultFilePolicy.ValidateNativeFileState(
        new(0x80, 1, 1, false, false), false);
    var rejected = new Security4663LiveResultNativeFileState[]
    {
        new(0x400, 0, 1, false, false),
        new(0x80, 1, 1, false, false),
        new(0x80, 4_097, 1, false, false),
        new(0x80, 0, 2, false, false),
        new(0x80, 0, 1, true, false),
        new(0x80, 0, 1, false, true)
    };
    foreach (var state in rejected)
    {
        ExpectInvalidData(
            () => Security4663LiveOneShotResultFilePolicy
                .ValidateNativeFileState(state, true),
            "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_STATE_INVALID");
    }
}

static void ValidatesSecurity4663LiveOneShotResultOperatorPlan()
{
    var plan = Security4663LiveOneShotResultOperator.BuildPlan();
    Security4663LiveOneShotResultOperator.ValidatePlan(plan);
    var commands = new[]
    {
        "plan", "prepare-slot", "empty-check", "check", "consume",
        "absent-check", "cleanup"
    };
    if (plan.SchemaVersion != 1 ||
        plan.Checkpoint != Security4663LiveOneShotResultLifecycle.Checkpoint ||
        plan.ResultPath != NativeSecurity4663LiveOneShotResultFileSlot.ResultPath ||
        plan.MaximumDocumentBytes != 4_096 || plan.MaximumResultAgeSeconds != 300 ||
        !plan.Commands.SequenceEqual(commands, StringComparer.Ordinal) ||
        !plan.RequiresAdministrator || !plan.ChecksProtectedRootAndFileAcl ||
        !plan.RejectsReparsePoints || !plan.RejectsHardLinks ||
        !plan.RequiresStrictUtf8 ||
        !plan.ValidatesManifestIdentitySignatureAndFreshness ||
        !plan.CheckIsReadOnly || !plan.ConsumeUsesExactAtomicHandleDelete ||
        !plan.CleanupIsFixedPathAndIdempotent ||
        !plan.CleanupAllowsBoundedEmptyPartialOrValidFile ||
        plan.ReadsEvents || plan.SignsData || plan.StartsOrMutatesService ||
        plan.MutatesRegistry || plan.MutatesAuditPolicy || plan.RetryEnabled ||
        plan.PollingEnabled || plan.TransportEnabled ||
        plan.InboundListenerEnabled || plan.CommandChannelEnabled ||
        plan.ResponseActionEnabled || plan.RuntimeWired ||
        Security4663LiveOneShotResultOperator.RuntimeWired ||
        NativeSecurity4663LiveOneShotResultOperatorStore.RuntimeWired ||
        typeof(ISensorIdentitySigner).IsAssignableFrom(
            typeof(CngMachineIdentityDescriptorReader)) ||
        typeof(CngMachineIdentityDescriptorReader).GetMethods().Any(
            method => method.Name.Contains("Sign", StringComparison.Ordinal)))
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_PLAN_INVALID");
    }
    for (var index = 0; index < commands.Length; index++)
    {
        if (Security4663LiveOneShotResultOperatorCommandParser.Parse(
                [commands[index]]) !=
            (Security4663LiveOneShotResultOperatorCommand)index)
        {
            throw new InvalidOperationException(
                "SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_COMMAND_INVALID");
        }
    }
    ExpectInvalidData(
        () => Security4663LiveOneShotResultOperatorCommandParser.Parse(["write"]),
        "SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_COMMAND_INVALID");
    ExpectInvalidData(
        () => Security4663LiveOneShotResultOperator.ValidatePlan(
            plan with { TransportEnabled = true }),
        "SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_PLAN_INVALID");

    if (NativeSecurity4663LiveOneShotResultOperatorStore
            .EvaluateCleanupPathState(null, null) ||
        NativeSecurity4663LiveOneShotResultOperatorStore
            .EvaluateCleanupPathState(FileAttributes.Directory, null) ||
        !NativeSecurity4663LiveOneShotResultOperatorStore
            .EvaluateCleanupPathState(FileAttributes.Directory, FileAttributes.Normal))
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_RESULT_CLEANUP_PATH_INVALID");
    }
    ExpectInvalidData(
        () => NativeSecurity4663LiveOneShotResultOperatorStore
            .EvaluateCleanupPathState(null, FileAttributes.Normal),
        "SENSOR_C2F_SECURITY_4663_RESULT_CLEANUP_PATH_INVALID");
    ExpectInvalidData(
        () => NativeSecurity4663LiveOneShotResultOperatorStore
            .EvaluateCleanupPathState(FileAttributes.Normal, null),
        "SENSOR_C2F_SECURITY_4663_RESULT_SLOT_ROOT_INVALID");
}

static void ValidatesSecurity4663LiveOneShotResultOperatorWorkflow()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    using var identity = new FakeSensorIdentitySigner();
    var manifest = new InstallManifestBinding(
        commit, identity.Descriptor.CertificateFingerprintSha256,
        new string('b', 64));
    var approval = Security4663LiveConsumedApproval(
        identity, commit, now.AddSeconds(-1));
    var slot = new FakeSecurity4663LiveOneShotResultOperatorStore();
    var prepared = Security4663LiveOneShotResultOperator.PrepareSlot(
        slot, identity.Descriptor, manifest, now);
    var empty = Security4663LiveOneShotResultOperator.EmptyCheck(
        slot, identity.Descriptor, manifest, now);
    var resultStore = new FakeSecurity4663LiveOneShotResultStore();
    _ = Security4663LiveOneShotResultLifecycle.CreateAndWrite(
        resultStore, identity, commit, approval, now, now.AddSeconds(1),
        Security4663LiveNoMatchResult(), now.AddSeconds(2));
    slot.Document = resultStore.Document;
    var checkedResult = Security4663LiveOneShotResultOperator.Check(
        slot, identity.Descriptor, manifest, now.AddSeconds(2));
    var consumed = Security4663LiveOneShotResultOperator.Consume(
        slot, identity.Descriptor, manifest, now.AddSeconds(2));
    var absent = Security4663LiveOneShotResultOperator.AbsentCheck(
        slot, identity.Descriptor, manifest, now.AddSeconds(2));
    var cleanupAbsent = Security4663LiveOneShotResultOperator.Cleanup(slot);
    slot.Prepared = true;
    slot.Document = "{partial";
    var cleanupPartial = Security4663LiveOneShotResultOperator.Cleanup(slot);
    if (prepared.State != "empty" || empty.State != "empty" ||
        checkedResult.State != "valid" || checkedResult.ReadState != "no-match" ||
        checkedResult.EventsRead != 0 || !checkedResult.ResultPresent ||
        consumed.State != "consumed" || !consumed.ResultConsumed ||
        consumed.RecoveryRemoved || consumed.ResultPresent ||
        absent.State != "absent" || cleanupAbsent.State != "absent" ||
        cleanupAbsent.ResultConsumed || cleanupAbsent.RecoveryRemoved ||
        cleanupPartial.State != "removed" || cleanupPartial.ResultConsumed ||
        !cleanupPartial.RecoveryRemoved || slot.PrepareCount != 1 ||
        slot.ConsumeCount != 1 || slot.CleanupCount != 1 ||
        new[] { prepared, empty, checkedResult, consumed, absent,
            cleanupAbsent, cleanupPartial }.Any(value =>
                value.EventContentRead || value.DataSigned ||
                value.ServiceMutated || value.RegistryMutated ||
                value.AuditPolicyMutated || value.TransportEnabled ||
                value.CommandChannelEnabled || value.RuntimeWired))
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_RESULT_OPERATOR_WORKFLOW_INVALID");
    }
}

static void ValidatesSecurity4663LiveOneShotExecutionPlan()
{
    var plan = Security4663LiveOneShotExecution.BuildPlan();
    Security4663LiveOneShotExecution.ValidatePlan(plan);
    if (plan.SchemaVersion != 1 ||
        plan.Checkpoint != Security4663LiveOneShotApprovalLifecycle.Checkpoint ||
        plan.StartupArgument != "--security-4663-live-one-shot" ||
        plan.ServiceIdentity != "NT AUTHORITY\\LocalService" ||
        plan.ApprovalPath !=
            NativeSecurity4663LiveOneShotApprovalFileStore.ApprovalPath ||
        plan.ResultPath != NativeSecurity4663LiveOneShotResultFileSlot.ResultPath ||
        plan.FixedTargetPath != Security4663OneShotMachinePlan.BuildPlan().InertTargetPath ||
        plan.ProfileId != "credential-store-read" ||
        !plan.RequiresLocalServiceBeforeProtectedAccess ||
        !plan.RequiresPreStartOperatorTrigger || plan.WorkerTriggersTarget ||
        !plan.ConsumesApprovalExactlyOnce || !plan.WritesResultExactlyOnce ||
        plan.MaximumEventsRead != 1 || plan.MaximumQueryMilliseconds != 2_000 ||
        plan.MaximumTriggerWindowSeconds != 10 ||
        !plan.NativeEventAccessEnabled || plan.RawEventContentRetained ||
        plan.PersistsClassificationKey || plan.ContinuousCollectionEnabled ||
        plan.RetryEnabled || plan.PollingEnabled || plan.TransportEnabled ||
        plan.InboundListenerEnabled || plan.CommandChannelEnabled ||
        plan.ResponseActionEnabled || !plan.RuntimeWired ||
        !Security4663LiveOneShotExecution.RuntimeWired ||
        !Security4663LiveOneShotBoundedReader.RuntimeWired ||
        !Security4663LiveOneShotBoundedReader.NativeEventAccessEnabled ||
        !NativeSecurity4663LiveOneShotEventSource.RuntimeWired ||
        !NativeSecurity4663LiveOneShotEventSource.ServiceRegistered)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_EXECUTION_PLAN_INVALID");
    }
    ExpectInvalidData(
        () => Security4663LiveOneShotExecution.ValidatePlan(
            plan with { TransportEnabled = true }),
        "SENSOR_C2F_SECURITY_4663_EXECUTION_PLAN_INVALID");

    if (SensorStartupArguments.Parse(["--security-4663-live-one-shot"]) !=
            SensorStartupMode.Security4663LiveOneShot ||
        SensorStartupArguments.Resolve([], new FakeSensorStartupModeSource(
            "--security-4663-live-one-shot")) !=
            SensorStartupMode.Security4663LiveOneShot)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_STARTUP_MODE_INVALID");
    }

    if (Security4663LiveOneShotExecution.PublicFailureCode(
            new InvalidDataException("SENSOR_C2F_SECURITY_4663_APPROVAL_INVALID")) !=
            "SENSOR_C2F_SECURITY_4663_APPROVAL_INVALID" ||
        Security4663LiveOneShotExecution.PublicFailureCode(
            new InvalidOperationException("private path detail")) !=
            "SENSOR_C2F_SECURITY_4663_EXECUTION_FAILED")
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_FAILURE_CODE_INVALID");
    }
}

static void ValidatesSecurity4663GenuineMatchValidationPlan()
{
    var plan = Security4663GenuineMatchValidation.BuildPlan();
    Security4663GenuineMatchValidation.ValidatePlan(plan);
    if (plan.SchemaVersion != 1 ||
        plan.Checkpoint != "gate-c2g-security-4663-genuine-match" ||
        plan.ServiceIdentity != "NT AUTHORITY\\LocalService" ||
        !plan.RequiresLocalServiceBeforeProtectedAccess ||
        !plan.RequiresPreStartOperatorTrigger ||
        !plan.RequiresFixedPostTriggerSettlement ||
        plan.TriggerSettlementMilliseconds != 2_000 ||
        plan.MaximumEventsRead != 1 || plan.MaximumQueries != 1 ||
        plan.MaximumQueryMilliseconds != 2_000 ||
        plan.MaximumTriggerWindowSeconds != 10 ||
        !plan.RequiresGenuineMatch || plan.RequiredEventsRead != 1 ||
        !plan.RequiresStrictRollback || plan.RawEventContentRetained ||
        plan.ContinuousCollectionEnabled || plan.RetryEnabled ||
        plan.PollingEnabled || plan.TelemetryEnabled ||
        plan.TransportEnabled || plan.IpcEnabled ||
        plan.InboundListenerEnabled || plan.CommandChannelEnabled ||
        plan.ResponseActionEnabled || plan.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2G_SECURITY_4663_PLAN_INVALID");
    }
    ExpectInvalidData(
        () => Security4663GenuineMatchValidation.ValidatePlan(
            plan with { MaximumQueries = 2 }),
        "SENSOR_C2G_SECURITY_4663_PLAN_INVALID");
    ExpectInvalidData(
        () => Security4663GenuineMatchValidation.ValidatePlan(
            plan with { TelemetryEnabled = true }),
        "SENSOR_C2G_SECURITY_4663_PLAN_INVALID");
}

static void ValidatesSecurity4663LiveFailureReceipt()
{
    var exact = Security4663LiveOneShotFailureReceiptLifecycle.Create(
        new InvalidDataException(
            "SENSOR_C2F_SECURITY_4663_EXECUTION_WINDOW_INVALID"));
    if (!Security4663LiveOneShotFailureReceiptLifecycle.TryRead(
            exact, out var exactCode) ||
        exactCode != "SENSOR_C2F_SECURITY_4663_EXECUTION_WINDOW_INVALID" ||
        Encoding.UTF8.GetByteCount(exact) >
            Security4663LiveOneShotFailureReceiptLifecycle.MaximumDocumentBytes)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_FAILURE_RECEIPT_INVALID");
    }
    var generic = Security4663LiveOneShotFailureReceiptLifecycle.Create(
        new InvalidOperationException("private machine detail"));
    if (!Security4663LiveOneShotFailureReceiptLifecycle.TryRead(
            generic, out var genericCode) ||
        genericCode != "SENSOR_C2F_SECURITY_4663_EXECUTION_FAILED")
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_FAILURE_RECEIPT_INVALID");
    }
    var store = new FakeSecurity4663LiveOneShotResultStore();
    if (!Security4663LiveOneShotFailureReceiptLifecycle.TryWrite(
            store,
            new InvalidDataException(
                "SENSOR_C2F_SECURITY_4663_EXECUTION_WINDOW_INVALID")) ||
        store.WriteCount != 1 ||
        !Security4663LiveOneShotFailureReceiptLifecycle.TryRead(
            store.Document ?? string.Empty, out var writtenCode) ||
        writtenCode != "SENSOR_C2F_SECURITY_4663_EXECUTION_WINDOW_INVALID")
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_FAILURE_RECEIPT_WRITE_INVALID");
    }
    var malformed = exact.TrimEnd('}') + ",\"extra\":false}";
    ExpectInvalidData(
        () => Security4663LiveOneShotFailureReceiptLifecycle.TryRead(
            malformed, out _),
        "SENSOR_C2F_SECURITY_4663_FAILURE_RECEIPT_INVALID");
    if (Security4663LiveOneShotFailureReceiptLifecycle.TryRead(
        "{\"purpose\":\"different\"}", out _))
    {
        throw new InvalidOperationException(
            "non-diagnostic document accepted as a failure receipt");
    }
}

static void ValidatesSecurity4663LiveOneShotExecution()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var approvedAt = new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    var now = approvedAt.AddSeconds(1);
    using var identity = new FakeSensorIdentitySigner();
    var manifest = new InstallManifestBinding(
        commit, identity.Descriptor.CertificateFingerprintSha256,
        new string('b', 64));
    var approvalStore = new FakeSecurity4663LiveOneShotApprovalStore();
    _ = Security4663LiveOneShotApprovalLifecycle.CreateAndWrite(
        approvalStore,
        identity,
        commit,
        Security4663ReadinessCheck.Check(
            FakeSecurity4663ReadinessProbe.Ready()),
        42,
        approvedAt.UtcDateTime,
        Security4663ApprovalNonce());
    var source = new FakeSecurity4663OneShotEventSource(
        new(Security4663OneShotReadState.NoMatch, null));
    var reader = new Security4663LiveOneShotBoundedReader(source);
    var resultStore = new FakeSecurity4663LiveOneShotResultStore();
    var execution = Security4663LiveOneShotExecution.Execute(
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        new FakeInstallManifestBindingReader(manifest),
        approvalStore,
        reader,
        resultStore,
        identity,
        new FixedTestTimeProvider(now.UtcDateTime),
        CancellationToken.None);
    var validated = Security4663LiveOneShotResultLifecycle.Validate(
        resultStore.Document ?? string.Empty,
        identity.Descriptor,
        commit,
        now);
    if (execution.State != "completed" || execution.ReadState != "no-match" ||
        execution.EventsRead != 0 || !execution.LocalServiceIdentityValidated ||
        !execution.ApprovalConsumed || !execution.ResultWritten ||
        execution.RawEventContentRetained ||
        execution.ContinuousCollectionEnabled || execution.RetryEnabled ||
        execution.PollingEnabled || execution.TransportEnabled ||
        execution.InboundListenerEnabled || execution.CommandChannelEnabled ||
        execution.ResponseActionEnabled || source.Calls != 1 ||
        source.LastQuery?.MaximumEventsRead != 1 ||
        source.LastQuery?.MaximumQueryMilliseconds != 2_000 ||
        source.LastQuery?.LogName != "Security" ||
        source.LastQuery?.XPath !=
            Security4663OneShotBoundedReader.BuildXPath(42) ||
        approvalStore.ConsumeCount != 1 || approvalStore.Document is not null ||
        resultStore.WriteCount != 1 || validated.ReadState != "no-match" ||
        validated.EventsRead != 0 || validated.GenuineLiveEligible ||
        validated.RuntimeCollectionEnabled || validated.TransportEnabled)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_EXECUTION_INVALID");
    }

    var matchApprovalStore = new FakeSecurity4663LiveOneShotApprovalStore();
    _ = Security4663LiveOneShotApprovalLifecycle.CreateAndWrite(
        matchApprovalStore,
        identity,
        commit,
        Security4663ReadinessCheck.Check(
            FakeSecurity4663ReadinessProbe.Ready()),
        42,
        approvedAt.UtcDateTime,
        Security4663ApprovalNonce());
    var fixture = Security4663OneShotFixture(
        approvedAt.AddMilliseconds(500), 43);
    var matchSource = new FakeSecurity4663OneShotEventSource(
        new(Security4663OneShotReadState.Match,
            Security4663OneShotEventXml(fixture)));
    var matchReader = new Security4663LiveOneShotBoundedReader(matchSource);
    var matchStore = new FakeSecurity4663LiveOneShotResultStore();
    var matchExecution = Security4663LiveOneShotExecution.Execute(
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        new FakeInstallManifestBindingReader(manifest),
        matchApprovalStore,
        matchReader,
        matchStore,
        identity,
        new FixedTestTimeProvider(now.UtcDateTime),
        CancellationToken.None);
    var match = Security4663LiveOneShotResultLifecycle.Validate(
        matchStore.Document ?? string.Empty,
        identity.Descriptor,
        commit,
        now);
    if (matchExecution.ReadState != "match" ||
        matchExecution.EventsRead != 1 ||
        match.ReadState != "match" || match.EventsRead != 1 ||
        match.Provider != "windows-security" ||
        match.Channel != "security" ||
        match.EventFamily != "file-access" ||
        match.ObjectClass != "credential-store" ||
        match.Action != "read" ||
        match.SubjectClass != "other" ||
        match.ActorTrust != "unknown" ||
        match.SourceRecordTagHmacSha256?.Length != 64 ||
        match.LocalClassificationComplete != false ||
        match.GenuineLiveEligible || match.RawEventContentRetained ||
        match.RuntimeCollectionEnabled || match.RetryEnabled ||
        match.PollingEnabled || match.TransportEnabled ||
        match.InboundListenerEnabled || match.CommandChannelEnabled ||
        match.ResponseActionEnabled || matchApprovalStore.ConsumeCount != 1 ||
        matchSource.Calls != 1 || matchStore.WriteCount != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_C2F_SECURITY_4663_MATCH_EXECUTION_INVALID");
    }
}

static void RejectsSecurity4663LiveOneShotExecutionDrift()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var approvedAt = new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    var now = approvedAt.AddSeconds(1);
    using var identity = new FakeSensorIdentitySigner();
    var manifest = new InstallManifestBinding(
        commit, identity.Descriptor.CertificateFingerprintSha256,
        new string('b', 64));
    var approvalStore = new FakeSecurity4663LiveOneShotApprovalStore();
    _ = Security4663LiveOneShotApprovalLifecycle.CreateAndWrite(
        approvalStore, identity, commit,
        Security4663ReadinessCheck.Check(
            FakeSecurity4663ReadinessProbe.Ready()),
        42, approvedAt.UtcDateTime, Security4663ApprovalNonce());
    var reader = new FakeSecurity4663OneShotReader(
        new(Security4663OneShotReadState.NoMatch, null));
    var resultStore = new FakeSecurity4663LiveOneShotResultStore();
    AssertThrows<InvalidOperationException>(
        () => Security4663LiveOneShotExecution.Execute(
            new FakeSensorServiceIdentity("S-1-5-21-1000"),
            new FakeInstallManifestBindingReader(manifest),
            approvalStore, reader, resultStore, identity,
            new FixedTestTimeProvider(now.UtcDateTime),
            CancellationToken.None),
        "SENSOR_LOCALSERVICE_IDENTITY_REQUIRED");
    if (approvalStore.ReadCount != 1 || approvalStore.ConsumeCount != 0 ||
        reader.Calls != 0 || resultStore.WriteCount != 0)
    {
        throw new InvalidOperationException(
            "live execution reached authority before LocalService validation");
    }

    var source = new FakeSecurity4663OneShotEventSource(
        new(Security4663OneShotReadState.NoMatch, null));
    var liveReader = new Security4663LiveOneShotBoundedReader(source);
    ExpectInvalidData(
        () => liveReader.ReadOne(new(
            1,
            Security4663OneShotMachinePlan.Checkpoint,
            "Microsoft-Windows-Security-Auditing", "Security", 4663, 0,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            42, approvedAt, now, 2_000, 1), CancellationToken.None),
        "SENSOR_C2F_SECURITY_4663_READ_REQUEST_INVALID");
    if (source.Calls != 0)
    {
        throw new InvalidOperationException(
            "cross-domain request reached the live event source");
    }
}

static void ValidatesSecurity4663OneShotResultLifecycle()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    using var identity = new FakeSensorIdentitySigner();
    var approvalStore = new FakeSecurity4663OneShotApprovalStore();
    _ = Security4663OneShotApprovalLifecycle.CreateAndWrite(
        approvalStore,
        identity,
        commit,
        42,
        now.UtcDateTime,
        Security4663ApprovalNonce());
    var approvalJson = approvalStore.Document ?? throw new InvalidOperationException(
        "approval fixture missing");
    var store = new FakeSecurity4663OneShotResultStore();
    var result = Security4663OneShotResultLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        approvalJson,
        now.AddSeconds(1),
        now.AddSeconds(2),
        Security4663NoMatchResult(),
        now.AddSeconds(2));

    if (
        result.SchemaVersion != 1 ||
        result.Profile != Security4663OneShotResultLifecycle.Profile ||
        result.Checkpoint != Security4663OneShotMachinePlan.Checkpoint ||
        result.TargetProfileId != "credential-store-read" ||
        result.ReadState != "no-match" ||
        result.EventsRead != 0 ||
        result.Provider is not null ||
        result.Channel is not null ||
        result.EventFamily is not null ||
        result.OccurredAt is not null ||
        result.SourceRecordTagHmacSha256 is not null ||
        result.ActorTrust is not null ||
        result.Action is not null ||
        result.SubjectClass is not null ||
        result.ObjectClass is not null ||
        result.Outcome is not null ||
        result.BaselineState is not null ||
        result.VisibilityState is not null ||
        result.TargetSaclVerified is not null ||
        result.LocalClassificationComplete is not null ||
        result.GenuineLiveEligible ||
        result.RawEventContentRetained ||
        result.RuntimeCollectionEnabled ||
        result.RetryEnabled ||
        result.PollingEnabled ||
        result.TransportEnabled ||
        result.InboundListenerEnabled ||
        result.CommandChannelEnabled ||
        result.ResponseActionEnabled ||
        result.TriggerStartedAt != "2026-08-09T10:00:01.000Z" ||
        result.TriggerCompletedAt != "2026-08-09T10:00:02.000Z" ||
        result.InstalledCommit != commit ||
        result.CertificateFingerprintSha256 !=
            identity.Descriptor.CertificateFingerprintSha256 ||
        result.ApprovalEnvelopeSha256 !=
            Security4663OneShotResultLifecycle.HashApprovalEnvelope(
                approvalJson) ||
        result.CreatedAt != "2026-08-09T10:00:02.000Z" ||
        Convert.FromBase64String(result.SignatureBase64).Length != 64 ||
        store.WriteCount != 1 ||
        string.IsNullOrEmpty(store.Document) ||
        Encoding.UTF8.GetByteCount(store.Document) > 4_096 ||
        Security4663OneShotResultLifecycle.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_RESULT_LIFECYCLE_INVALID");
    }

    var checkedResult = Security4663OneShotResultLifecycle.ReadAndValidate(
        store,
        identity.Descriptor,
        commit,
        now.AddSeconds(2));
    var consumed = Security4663OneShotResultLifecycle.Consume(
        store,
        identity.Descriptor,
        commit,
        now.AddSeconds(2));
    if (
        checkedResult != result ||
        consumed != result ||
        store.ConsumeCount != 1 ||
        store.Document is not null)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_RESULT_CONSUME_INVALID");
    }
}

static void ValidatesSecurity4663OneShotMatchResult()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    using var identity = new FakeSensorIdentitySigner();
    var approvalJson = Security4663ResultApprovalJson(
        identity,
        commit,
        now.AddSeconds(-1));
    var store = new FakeSecurity4663OneShotResultStore();
    var sourceResult = Security4663MatchResult();
    var result = Security4663OneShotResultLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        approvalJson,
        now,
        now.AddSeconds(1),
        sourceResult,
        now.AddSeconds(1));
    var json = store.Document ?? string.Empty;
    var secondStore = new FakeSecurity4663OneShotResultStore();
    var second = Security4663OneShotResultLifecycle.CreateAndWrite(
        secondStore,
        identity,
        commit,
        approvalJson,
        now,
        now.AddSeconds(1),
        sourceResult,
        now.AddSeconds(1));
    if (
        result.ReadState != "match" ||
        result.EventsRead != 1 ||
        result.Provider != "windows-security" ||
        result.Channel != "security" ||
        result.EventFamily != "file-access" ||
        result.OccurredAt != "2026-08-09T10:00:00.000Z" ||
        result.SourceRecordTagHmacSha256 is null ||
        result.SourceRecordTagHmacSha256.Length != 64 ||
        result.SourceRecordTagHmacSha256 ==
            second.SourceRecordTagHmacSha256 ||
        result.ActorTrust != "untrusted" ||
        result.Action != "read" ||
        result.SubjectClass != "other" ||
        result.ObjectClass != "credential-store" ||
        result.Outcome != "success" ||
        result.BaselineState != "rare" ||
        result.VisibilityState != "unknown" ||
        result.TargetSaclVerified != true ||
        result.LocalClassificationComplete != true ||
        result.GenuineLiveEligible ||
        result.RawEventContentRetained ||
        json.Contains("SubjectUser", StringComparison.Ordinal) ||
        json.Contains("ObjectName", StringComparison.Ordinal) ||
        json.Contains("ProcessName", StringComparison.Ordinal) ||
        json.Contains("EventXml", StringComparison.Ordinal) ||
        json.Contains("baselineRecordId", StringComparison.Ordinal))
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_RESULT_RAW_RETENTION_INVALID");
    }
}

static void RejectsSecurity4663OneShotResultDrift()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    using var identity = new FakeSensorIdentitySigner();
    var approvalJson = Security4663ResultApprovalJson(
        identity,
        commit,
        now.AddSeconds(-1));
    var store = new FakeSecurity4663OneShotResultStore();
    _ = Security4663OneShotResultLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        approvalJson,
        now,
        now.AddSeconds(1),
        Security4663NoMatchResult(),
        now.AddSeconds(1));
    var json = store.Document ?? throw new InvalidOperationException(
        "result fixture missing");
    ExpectInvalidData(
        () => Security4663OneShotResultLifecycle.Validate(
            json.Replace(
                "\"eventsRead\":0",
                "\"eventsRead\":1",
                StringComparison.Ordinal),
            identity.Descriptor,
            commit,
            now.AddSeconds(1)),
        "SENSOR_C2E_SECURITY_4663_RESULT_INVALID");
    ExpectInvalidData(
        () => Security4663OneShotResultLifecycle.Validate(
            json,
            identity.Descriptor,
            commit,
            now.AddMinutes(6)),
        "SENSOR_C2E_SECURITY_4663_RESULT_INVALID");
    ExpectInvalidData(
        () => Security4663OneShotResultLifecycle.Validate(
            json,
            identity.Descriptor,
            commit,
            now),
        "SENSOR_C2E_SECURITY_4663_RESULT_INVALID");
    ExpectInvalidData(
        () => Security4663OneShotResultLifecycle.CreateAndWrite(
            store,
            identity,
            commit,
            approvalJson,
            now,
            now.AddSeconds(1),
            Security4663NoMatchResult(),
            now.AddSeconds(1)),
        "SENSOR_C2E_SECURITY_4663_RESULT_ALREADY_EXISTS");

    var cleanStore = new FakeSecurity4663OneShotResultStore();
    ExpectInvalidData(
        () => Security4663OneShotResultLifecycle.CreateAndWrite(
            cleanStore,
            identity,
            commit,
            approvalJson,
            now,
            now.AddSeconds(1),
            Security4663MatchResult() with { EventsRead = 0 },
            now.AddSeconds(1)),
        "SENSOR_C2E_SECURITY_4663_RESULT_CONTEXT_INVALID");
    var staleMatch = Security4663MatchResult();
    ExpectInvalidData(
        () => Security4663OneShotResultLifecycle.CreateAndWrite(
            cleanStore,
            identity,
            commit,
            approvalJson,
            now,
            now.AddSeconds(1),
            staleMatch with
            {
                Classification = staleMatch.Classification! with
                {
                    SourceRecordId = 42
                }
            },
            now.AddSeconds(1)),
        "SENSOR_C2E_SECURITY_4663_RESULT_CONTEXT_INVALID");
    ExpectInvalidData(
        () => Security4663OneShotResultLifecycle.CreateAndWrite(
            cleanStore,
            identity,
            commit,
            approvalJson,
            now,
            now.AddSeconds(1),
            Security4663NoMatchResult() with { RuntimeWired = true },
            now.AddSeconds(1)),
        "SENSOR_C2E_SECURITY_4663_RESULT_CONTEXT_INVALID");
    using var corrupt = new FakeSensorIdentitySigner();
    var corruptApproval = Security4663ResultApprovalJson(
        corrupt,
        commit,
        now.AddSeconds(-1));
    corrupt.CorruptSignature = true;
    ExpectInvalidData(
        () => Security4663OneShotResultLifecycle.CreateAndWrite(
            cleanStore,
            corrupt,
            commit,
            corruptApproval,
            now,
            now.AddSeconds(1),
            Security4663NoMatchResult(),
            now.AddSeconds(1)),
        "SENSOR_C2E_SECURITY_4663_RESULT_INVALID");
    if (cleanStore.WriteCount != 0 || cleanStore.Document is not null)
    {
        throw new InvalidOperationException(
            "invalid normalized result was persisted");
    }
}

static Security4663OneShotResult Security4663NoMatchResult() =>
    new(
        1,
        Security4663OneShotMachinePlan.Checkpoint,
        Security4663OneShotReadState.NoMatch,
        0,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        null);

static Security4663OneShotResult Security4663MatchResult()
{
    var key = InertClassificationKey();
    var fixture = InertSecurity4663Fixture();
    var classification = InertWindowsSecurity4663LocalClassifier.Classify(
        fixture,
        InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
        InertTargetBinding(
            fixture,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            key),
        InertProcessBinding(fixture, key),
        1,
        null,
        key);
    return new Security4663OneShotResult(
        1,
        Security4663OneShotMachinePlan.Checkpoint,
        Security4663OneShotReadState.Match,
        1,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        classification);
}

static void ValidatesSecurity4663OneShotResultFileSlot()
{
    var plan = Security4663OneShotResultFilePolicy.BuildPlan();
    Security4663OneShotResultFilePolicy.ValidatePlan(plan);
    if (
        plan.SchemaVersion != 1 ||
        plan.ResultPath !=
            NativeSecurity4663OneShotResultFileSlot.ResultPath ||
        plan.ResultPath != Security4663OneShotOperatorCeremony
            .BuildPlan().ResultPath ||
        plan.MaximumDocumentBytes != 4_096 ||
        plan.OwnerSid != "S-1-5-32-544" ||
        plan.ServiceSid != "S-1-5-19" ||
        plan.ServiceRightsMask != 0x00000002 ||
        !plan.RequiresAdministratorToCreate ||
        !plan.RequiresPrecreatedEmptyFile ||
        !plan.RequiresProtectedDacl ||
        !plan.RejectsInheritedRules ||
        !plan.RejectsReparsePoints ||
        !plan.RejectsStaleContent ||
        !plan.UsesOpenExisting ||
        !plan.UsesOneExclusiveWriteThroughHandle ||
        plan.AllowsOverwrite ||
        plan.AllowsServiceCreate ||
        plan.AllowsServiceDelete ||
        plan.AllowsServiceAclChange ||
        plan.AllowsServiceDirectoryAccess ||
        plan.RetryEnabled ||
        plan.PollingEnabled ||
        plan.TransportEnabled ||
        plan.CommandChannelEnabled ||
        plan.RuntimeWired ||
        NativeSecurity4663OneShotResultFileSlot.RuntimeWired ||
        NativeSecurity4663OneShotResultFileStore.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_PLAN_INVALID");
    }

    var acl = Security4663OneShotResultFilePolicy.Snapshot(
        Security4663OneShotResultFilePolicy.CreateFileSecurity());
    Security4663OneShotResultFilePolicy.ValidateFileAcl(acl);
    var serviceRule = acl.Rules.Single(rule => rule.Sid == "S-1-5-19");
    if (
        serviceRule.RightsMask != 0x00000002 ||
        acl.Rules.Any(rule =>
            rule.IsInherited ||
            rule.Inheritance != InheritanceFlags.None ||
            rule.Propagation != PropagationFlags.None))
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_ACL_INVALID");
    }

    var store = new NativeSecurity4663OneShotResultFileStore();
    if (store.ReadExisting() is not null)
    {
        throw new InvalidOperationException(
            "result writer performed an unexpected read");
    }
    ExpectInvalidData(
        () => store.ConsumeExact("{}"),
        "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_CONSUME_FORBIDDEN");
}

static void RejectsSecurity4663OneShotResultFileSlotDrift()
{
    var plan = Security4663OneShotResultFilePolicy.BuildPlan();
    var driftedPlans = new[]
    {
        plan with { ResultPath = plan.ResultPath + ".alternate" },
        plan with { ServiceRightsMask = 0x00000006 },
        plan with { RequiresPrecreatedEmptyFile = false },
        plan with { UsesOpenExisting = false },
        plan with { UsesOneExclusiveWriteThroughHandle = false },
        plan with { AllowsOverwrite = true },
        plan with { AllowsServiceCreate = true },
        plan with { AllowsServiceDelete = true },
        plan with { AllowsServiceAclChange = true },
        plan with { AllowsServiceDirectoryAccess = true },
        plan with { TransportEnabled = true },
        plan with { FullControlSids = ["S-1-5-18"] }
    };
    foreach (var drifted in driftedPlans)
    {
        ExpectInvalidData(
            () => Security4663OneShotResultFilePolicy.ValidatePlan(drifted),
            "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_PLAN_INVALID");
    }

    var acl = Security4663OneShotResultFilePolicy.Snapshot(
        Security4663OneShotResultFilePolicy.CreateFileSecurity());
    var serviceRule = acl.Rules.Single(rule => rule.Sid == "S-1-5-19");
    var driftedAcls = new[]
    {
        acl with { OwnerSid = "S-1-5-18" },
        acl with { IsProtected = false },
        acl with
        {
            Rules = acl.Rules.Select(rule => rule == serviceRule
                ? rule with { RightsMask = 0x00000006 }
                : rule).ToArray()
        },
        acl with
        {
            Rules = acl.Rules.Select(rule => rule == serviceRule
                ? rule with { IsInherited = true }
                : rule).ToArray()
        },
        acl with
        {
            Rules = acl.Rules.Append(serviceRule with
            {
                Sid = "S-1-5-11"
            }).ToArray()
        }
    };
    foreach (var drifted in driftedAcls)
    {
        ExpectInvalidData(
            () => Security4663OneShotResultFilePolicy.ValidateFileAcl(
                drifted),
            "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_ACL_INVALID");
    }
}

static void RejectsSecurity4663OneShotResultNativeStateDrift()
{
    Security4663OneShotResultFilePolicy.ValidateNativeFileState(
        0x00000080,
        0,
        1,
        deletePending: false,
        directory: false);
    var rejected = new (uint Attributes, long Length, uint Links,
        bool DeletePending, bool Directory)[]
    {
        (0x00000400, 0, 1, false, false),
        (0x00000080, 1, 1, false, false),
        (0x00000080, 4_096, 1, false, false),
        (0x00000080, 0, 2, false, false),
        (0x00000080, 0, 1, true, false),
        (0x00000080, 0, 1, false, true)
    };
    foreach (var state in rejected)
    {
        ExpectInvalidData(
            () => Security4663OneShotResultFilePolicy.ValidateNativeFileState(
                state.Attributes,
                state.Length,
                state.Links,
                state.DeletePending,
                state.Directory),
            "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_STATE_INVALID");
    }
}

static void ValidatesSecurity4663OneShotApprovalFileStore()
{
    var plan = Security4663OneShotApprovalFilePolicy.BuildPlan();
    Security4663OneShotApprovalFilePolicy.ValidatePlan(plan);
    if (
        plan.SchemaVersion != 1 ||
        plan.ApprovalPath !=
            NativeSecurity4663OneShotApprovalFileStore.ApprovalPath ||
        plan.MaximumDocumentBytes != 4_096 ||
        plan.OwnerSid != "S-1-5-32-544" ||
        plan.ServiceSid != "S-1-5-19" ||
        plan.ServiceRightsMask != 0x00130089 ||
        !plan.RequiresProtectedDacl ||
        !plan.RequiresCreateNew ||
        !plan.RejectsReparsePoints ||
        !plan.UsesExclusiveConsumeHandle ||
        !plan.UsesHandleDispositionDelete ||
        plan.AllowsOverwrite ||
        plan.AllowsServiceWrite ||
        plan.RetryEnabled ||
        plan.PollingEnabled ||
        plan.TransportEnabled ||
        plan.CommandChannelEnabled ||
        !plan.RuntimeWired ||
        !NativeSecurity4663OneShotApprovalFileStore.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_PLAN_INVALID");
    }

    var acl = Security4663OneShotApprovalFilePolicy.Snapshot(
        Security4663OneShotApprovalFilePolicy.CreateFileSecurity());
    Security4663OneShotApprovalFilePolicy.ValidateFileAcl(acl);
    var serviceRule = acl.Rules.Single(rule => rule.Sid == "S-1-5-19");
    if (
        serviceRule.RightsMask != 0x00130089 ||
        acl.Rules.Any(rule => rule.IsInherited ||
            rule.Inheritance != InheritanceFlags.None ||
            rule.Propagation != PropagationFlags.None))
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_ACL_INVALID");
    }
}

static void ValidatesSecurity4663OneShotResultOperatorPlan()
{
    var plan = Security4663OneShotResultOperator.BuildPlan();
    Security4663OneShotResultOperator.ValidatePlan(plan);
    var commands = new[]
    {
        "plan", "prepare-slot", "empty-check", "check", "consume",
        "absent-check", "cleanup"
    };
    if (
        plan.SchemaVersion != 1 ||
        plan.ResultPath != NativeSecurity4663OneShotResultFileSlot.ResultPath ||
        plan.MaximumDocumentBytes != 4_096 ||
        plan.MaximumResultAgeSeconds != 300 ||
        !plan.Commands.SequenceEqual(commands, StringComparer.Ordinal) ||
        !plan.RequiresAdministrator ||
        !plan.ChecksProtectedRootAndFileAcl ||
        !plan.RejectsReparsePoints ||
        !plan.RejectsHardLinks ||
        !plan.RequiresStrictUtf8 ||
        !plan.ValidatesManifestIdentitySignatureAndFreshness ||
        !plan.CheckIsReadOnly ||
        !plan.ConsumeUsesExactAtomicHandleDelete ||
        !plan.CleanupIsFixedPathAndIdempotent ||
        !plan.CleanupAllowsBoundedEmptyPartialOrValidFile ||
        plan.ReadsEvents ||
        plan.SignsData ||
        plan.StartsOrMutatesService ||
        plan.MutatesRegistry ||
        plan.MutatesAuditPolicy ||
        plan.RetryEnabled ||
        plan.PollingEnabled ||
        plan.TransportEnabled ||
        plan.InboundListenerEnabled ||
        plan.CommandChannelEnabled ||
        plan.ResponseActionEnabled ||
        plan.RuntimeWired ||
        Security4663OneShotResultOperator.RuntimeWired ||
        NativeSecurity4663OneShotResultOperatorStore.RuntimeWired ||
        typeof(ISensorIdentitySigner).IsAssignableFrom(
            typeof(CngMachineIdentityDescriptorReader)) ||
        typeof(CngMachineIdentityDescriptorReader).GetMethods().Any(
            method => method.Name.Contains("Sign", StringComparison.Ordinal)))
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_RESULT_OPERATOR_PLAN_INVALID");
    }
    for (var index = 0; index < commands.Length; index++)
    {
        if (Security4663OneShotResultOperatorCommandParser.Parse([commands[index]]) !=
            (Security4663OneShotResultOperatorCommand)index)
        {
            throw new InvalidOperationException(
                "SENSOR_C2E_SECURITY_4663_RESULT_OPERATOR_COMMAND_INVALID");
        }
    }
    ExpectInvalidData(
        () => Security4663OneShotResultOperatorCommandParser.Parse(["write"]),
        "SENSOR_C2E_SECURITY_4663_RESULT_OPERATOR_COMMAND_INVALID");
    ExpectInvalidData(
        () => Security4663OneShotResultOperator.ValidatePlan(
            plan with { TransportEnabled = true }),
        "SENSOR_C2E_SECURITY_4663_RESULT_OPERATOR_PLAN_INVALID");
}

static void ValidatesSecurity4663OneShotResultOperatorWorkflow()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero);
    using var identity = new FakeSensorIdentitySigner();
    var manifest = new InstallManifestBinding(
        commit,
        identity.Descriptor.CertificateFingerprintSha256,
        new string('b', 64));
    var store = new FakeSecurity4663OneShotResultOperatorStore();

    var prepared = Security4663OneShotResultOperator.PrepareSlot(
        store, identity.Descriptor, manifest, now);
    var empty = Security4663OneShotResultOperator.EmptyCheck(
        store, identity.Descriptor, manifest, now);
    var resultStore = new FakeSecurity4663OneShotResultStore();
    _ = Security4663OneShotResultLifecycle.CreateAndWrite(
        resultStore,
        identity,
        commit,
        Security4663ResultApprovalJson(identity, commit, now.AddSeconds(-1)),
        now,
        now.AddSeconds(1),
        Security4663NoMatchResult(),
        now.AddSeconds(1));
    store.Document = resultStore.Document;
    var checkedResult = Security4663OneShotResultOperator.Check(
        store, identity.Descriptor, manifest, now.AddSeconds(1));
    var consumed = Security4663OneShotResultOperator.Consume(
        store, identity.Descriptor, manifest, now.AddSeconds(1));
    var absent = Security4663OneShotResultOperator.AbsentCheck(
        store, identity.Descriptor, manifest, now.AddSeconds(1));
    var cleanupAbsent = Security4663OneShotResultOperator.Cleanup(
        store);
    store.Prepared = true;
    store.Document = "partial";
    var cleanupPartial = Security4663OneShotResultOperator.Cleanup(
        store);

    if (
        prepared.State != "empty" || empty.State != "empty" ||
        checkedResult.State != "valid" || checkedResult.ReadState != "no-match" ||
        checkedResult.EventsRead != 0 || !checkedResult.ResultPresent ||
        consumed.State != "consumed" || !consumed.ResultConsumed ||
        consumed.RecoveryRemoved ||
        consumed.ResultPresent || absent.State != "absent" ||
        cleanupAbsent.State != "absent" || cleanupAbsent.ResultConsumed ||
        cleanupAbsent.RecoveryRemoved ||
        cleanupAbsent.InstalledCommit is not null ||
        cleanupAbsent.IdentityFingerprintSha256 is not null ||
        cleanupPartial.State != "removed" || cleanupPartial.ResultConsumed ||
        !cleanupPartial.RecoveryRemoved ||
        cleanupPartial.InstalledCommit is not null ||
        cleanupPartial.IdentityFingerprintSha256 is not null ||
        store.PrepareCount != 1 || store.ConsumeCount != 1 ||
        store.CleanupCount != 1 || store.Document is not null ||
        new[] { prepared, empty, checkedResult, consumed, absent,
            cleanupAbsent, cleanupPartial }.Any(value =>
                value.EventContentRead || value.DataSigned ||
                value.ServiceMutated || value.RegistryMutated ||
                value.AuditPolicyMutated || value.TransportEnabled ||
                value.CommandChannelEnabled || value.RuntimeWired))
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_RESULT_OPERATOR_WORKFLOW_INVALID");
    }

    store.Prepared = true;
    store.Document = resultStore.Document;
    ExpectInvalidData(
        () => Security4663OneShotResultOperator.Check(
            store, identity.Descriptor, manifest, now.AddMinutes(6)),
        "SENSOR_C2E_SECURITY_4663_RESULT_INVALID");
    ExpectInvalidData(
        () => Security4663OneShotResultOperator.Check(
            store,
            identity.Descriptor,
            manifest with { Fingerprint = new string('c', 64) },
            now.AddSeconds(1)),
        "SENSOR_C2E_SECURITY_4663_RESULT_OPERATOR_CONTEXT_INVALID");
}

static void RejectsSecurity4663OneShotApprovalFileStoreDrift()
{
    var plan = Security4663OneShotApprovalFilePolicy.BuildPlan();
    var driftedPlans = new[]
    {
        plan with { ApprovalPath = plan.ApprovalPath + ".alternate" },
        plan with { ServiceRightsMask = 0x0013019F },
        plan with { UsesExclusiveConsumeHandle = false },
        plan with { UsesHandleDispositionDelete = false },
        plan with { AllowsServiceWrite = true },
        plan with { RetryEnabled = true },
        plan with { RuntimeWired = false },
        plan with { FullControlSids = ["S-1-5-18"] }
    };
    foreach (var drifted in driftedPlans)
    {
        ExpectInvalidData(
            () => Security4663OneShotApprovalFilePolicy.ValidatePlan(drifted),
            "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_PLAN_INVALID");
    }

    var acl = Security4663OneShotApprovalFilePolicy.Snapshot(
        Security4663OneShotApprovalFilePolicy.CreateFileSecurity());
    var serviceRule = acl.Rules.Single(rule => rule.Sid == "S-1-5-19");
    var driftedAcls = new[]
    {
        acl with { OwnerSid = "S-1-5-18" },
        acl with { IsProtected = false },
        acl with
        {
            Rules = acl.Rules.Select(rule => rule == serviceRule
                ? rule with { RightsMask = 0x0013019F }
                : rule).ToArray()
        },
        acl with
        {
            Rules = acl.Rules.Select(rule => rule == serviceRule
                ? rule with { IsInherited = true }
                : rule).ToArray()
        },
        acl with
        {
            Rules = acl.Rules.Append(serviceRule with
            {
                Sid = "S-1-5-11"
            }).ToArray()
        }
    };
    foreach (var drifted in driftedAcls)
    {
        ExpectInvalidData(
            () => Security4663OneShotApprovalFilePolicy.ValidateFileAcl(
                drifted),
            "SENSOR_C2E_SECURITY_4663_APPROVAL_FILE_ACL_INVALID");
    }
}

static void ValidatesSecurity4663OneShotResultIndependentCleanup()
{
    if (
        NativeSecurity4663OneShotResultOperatorStore.EvaluateCleanupPathState(
            null, null) ||
        NativeSecurity4663OneShotResultOperatorStore.EvaluateCleanupPathState(
            FileAttributes.Directory, null) ||
        !NativeSecurity4663OneShotResultOperatorStore.EvaluateCleanupPathState(
            FileAttributes.Directory, FileAttributes.Normal))
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_RESULT_CLEANUP_PATH_INVALID");
    }
    ExpectInvalidData(
        () => NativeSecurity4663OneShotResultOperatorStore
            .EvaluateCleanupPathState(null, FileAttributes.Normal),
        "SENSOR_C2E_SECURITY_4663_RESULT_CLEANUP_PATH_INVALID");
    ExpectInvalidData(
        () => NativeSecurity4663OneShotResultOperatorStore
            .EvaluateCleanupPathState(FileAttributes.Normal, null),
        "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_ROOT_INVALID");
    ExpectInvalidData(
        () => NativeSecurity4663OneShotResultOperatorStore
            .EvaluateCleanupPathState(
                FileAttributes.Directory | FileAttributes.ReparsePoint,
                null),
        "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_ROOT_INVALID");
    ExpectInvalidData(
        () => NativeSecurity4663OneShotResultOperatorStore
            .EvaluateCleanupPathState(
                FileAttributes.Directory,
                FileAttributes.ReparsePoint),
        "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_FILE_INVALID");
    ExpectInvalidData(
        () => NativeSecurity4663OneShotResultOperatorStore
            .EvaluateCleanupPathState(
                FileAttributes.Directory,
                FileAttributes.Directory),
        "SENSOR_C2E_SECURITY_4663_RESULT_SLOT_FILE_INVALID");

    var absentStore = new FakeSecurity4663OneShotResultOperatorStore();
    var absent = Security4663OneShotResultOperator.Cleanup(absentStore);
    var partialStore = new FakeSecurity4663OneShotResultOperatorStore
    {
        Prepared = true,
        Document = "{partial"
    };
    var removed = Security4663OneShotResultOperator.Cleanup(partialStore);
    if (
        absent.State != "absent" || absent.ResultConsumed ||
        absent.RecoveryRemoved || absent.InstalledCommit is not null ||
        absent.IdentityFingerprintSha256 is not null ||
        removed.State != "removed" || removed.ResultConsumed ||
        !removed.RecoveryRemoved || removed.InstalledCommit is not null ||
        removed.IdentityFingerprintSha256 is not null ||
        partialStore.Document is not null || partialStore.Prepared)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_RESULT_INDEPENDENT_CLEANUP_INVALID");
    }
}

static void ValidatesDescriptorOnlyMachineIdentityBlob()
{
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var parameters = key.ExportParameters(includePrivateParameters: false);
    var blob = new byte[72];
    BinaryPrimitives.WriteUInt32LittleEndian(blob, 0x31534345);
    BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(4), 32);
    parameters.Q.X!.CopyTo(blob, 8);
    parameters.Q.Y!.CopyTo(blob, 40);
    var parsed = CngMachineIdentityDescriptorReader.ParseP256PublicBlob(blob);
    if (
        parsed.Q.X is null || parsed.Q.Y is null ||
        !parsed.Q.X.SequenceEqual(parameters.Q.X) ||
        !parsed.Q.Y.SequenceEqual(parameters.Q.Y) ||
        parsed.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
    {
        throw new InvalidOperationException(
            "SENSOR_NATIVE_PUBLIC_KEY_BLOB_INVALID");
    }

    var rejected = new[]
    {
        blob[..^1],
        blob.Select((value, index) => index == 0 ? (byte)0 : value).ToArray(),
        blob.Select((value, index) => index == 4 ? (byte)48 : value).ToArray()
    };
    foreach (var drifted in rejected)
    {
        try
        {
            _ = CngMachineIdentityDescriptorReader.ParseP256PublicBlob(drifted);
            throw new InvalidOperationException(
                "invalid public blob was accepted");
        }
        catch (CryptographicException error) when (
            error.Message == "SENSOR_NATIVE_PUBLIC_KEY_BLOB_INVALID")
        {
        }
    }
}

static void ValidatesSecurity4663OneShotApprovalOperatorPlan()
{
    var plan = Security4663OneShotApprovalOperator.BuildPlan();
    Security4663OneShotApprovalOperator.ValidatePlan(plan);
    var expectedCommands = new[]
    {
        "plan", "consume-proof-plan", "write", "check", "absent-check",
        "consume-exercise", "cleanup"
    };
    if (
        !plan.Commands.SequenceEqual(expectedCommands, StringComparer.Ordinal) ||
        !plan.RequiresAdministratorForMutation ||
        !plan.RequiresAdministratorForProtectedRead ||
        !plan.DerivesInstalledCommitFromProtectedManifest ||
        !plan.DerivesIdentityFromMachineKey ||
        !plan.CapturesBaselineFromMetadataOnly ||
        plan.AcceptsCallerInput ||
        plan.ReadsEvents ||
        plan.MaximumEventsRead != 0 ||
        plan.StartsService ||
        plan.MutatesService ||
        plan.ExternalCheckerMutatesApproval ||
        !plan.CleanupUsesOnlyFixedApprovalPath ||
        plan.RetryEnabled ||
        plan.PollingEnabled ||
        plan.TransportEnabled ||
        plan.InboundListenerEnabled ||
        plan.CommandChannelEnabled ||
        plan.ResponseActionEnabled ||
        plan.RuntimeWired ||
        Security4663OneShotApprovalOperator.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_PLAN_INVALID");
    }
    for (var index = 0; index < expectedCommands.Length; index++)
    {
        if (Security4663OneShotApprovalOperatorCommandParser.Parse(
            [expectedCommands[index]]) !=
            (Security4663OneShotApprovalOperatorCommand)index)
        {
            throw new InvalidOperationException(
                "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_COMMAND_INVALID");
        }
    }
    foreach (var rejected in new[] { "", "WRITE", "consume", "status" })
    {
        ExpectInvalidData(
            () => Security4663OneShotApprovalOperatorCommandParser.Parse(
                [rejected]),
            "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_COMMAND_INVALID");
    }
    ExpectInvalidData(
        () => Security4663OneShotApprovalOperator.ValidatePlan(
            plan with { CommandChannelEnabled = true }),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_PLAN_INVALID");
}

static void ValidatesSecurity4663OneShotApprovalOperatorWorkflow()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTime(2026, 8, 9, 12, 0, 0, DateTimeKind.Utc);
    using var identity = new FakeSensorIdentitySigner();
    var manifest = new InstallManifestBinding(
        commit,
        identity.Descriptor.CertificateFingerprintSha256,
        new string('b', 64));
    var store = new FakeSecurity4663OneShotApprovalStore();
    var source = new FakeSecurity4663LogMetadataSource(
        new Security4663LogMetadata(100, 5, false));
    var written = Security4663OneShotApprovalOperator.Write(
        store,
        identity,
        manifest,
        source,
        now,
        Security4663ApprovalNonce());
    var checkedApproval = Security4663OneShotApprovalOperator.Check(
        store,
        identity.Descriptor,
        manifest,
        now.AddSeconds(10));
    var consumed = Security4663OneShotApprovalOperator.ConsumeExercise(
        store,
        identity.Descriptor,
        manifest,
        now.AddSeconds(20));
    var absent = Security4663OneShotApprovalOperator.CheckAbsent(
        store,
        identity.Descriptor,
        manifest,
        now.AddSeconds(21));
    if (
        source.Calls != 1 ||
        written.Operation != "write" ||
        written.State != "approved" ||
        written.BaselineRecordId != 104 ||
        !written.ApprovalPresent ||
        written.ApprovalConsumed ||
        checkedApproval.Operation != "check" ||
        checkedApproval.State != "valid" ||
        !checkedApproval.ApprovalPresent ||
        checkedApproval.ApprovalConsumed ||
        consumed.Operation != "consume-exercise" ||
        consumed.State != "consumed" ||
        consumed.ApprovalPresent ||
        !consumed.ApprovalConsumed ||
        !consumed.OperatorConsumeOnly ||
        consumed.LocalServiceAuthorityProven ||
        consumed.EventContentRead ||
        consumed.EventsRead != 0 ||
        consumed.ServiceStarted ||
        consumed.ServiceMutated ||
        consumed.TransportEnabled ||
        consumed.CommandChannelEnabled ||
        consumed.RuntimeWired ||
        absent.Operation != "absent-check" ||
        absent.State != "absent" ||
        absent.ApprovalPresent ||
        absent.ApprovalConsumed ||
        absent.LocalServiceAuthorityProven ||
        absent.EventsRead != 0 ||
        absent.ServiceMutated ||
        store.AbsentCheckCount != 1 ||
        store.Document is not null)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_WORKFLOW_INVALID");
    }

    var blockedStore = new FakeSecurity4663OneShotApprovalStore();
    var blockedSource = new FakeSecurity4663LogMetadataSource(
        new Security4663LogMetadata(100, 5, false));
    ExpectInvalidData(
        () => Security4663OneShotApprovalOperator.Write(
            blockedStore,
            identity,
            manifest with { Fingerprint = new string('c', 64) },
            blockedSource,
            now,
            Security4663ApprovalNonce()),
        "SENSOR_C2E_SECURITY_4663_APPROVAL_OPERATOR_CONTEXT_INVALID");
    if (blockedSource.Calls != 0 || blockedStore.WriteCount != 0)
    {
        throw new InvalidOperationException(
            "operator context drift reached metadata or persistence");
    }
}

static void ValidatesSecurity4663ReadinessCheck()
{
    var probe = FakeSecurity4663ReadinessProbe.Ready();
    var result = Security4663ReadinessCheck.Check(probe);
    if (
        result.SchemaVersion != 1 ||
        result.Checkpoint != "gate-c2d-security-4663-machine-readiness" ||
        !result.Ready ||
        result.ServiceIdentityValidated ||
        result.ChangesChannelAccess ||
        result.ChangesAuditPolicy ||
        result.ChangesTargetSacl ||
        result.ReadsEvents ||
        result.EventsRead != 0 ||
        result.RuntimeCollectionEnabled ||
        result.TransportEnabled ||
        result.InboundListenerEnabled ||
        result.CommandChannelEnabled ||
        !result.Channel.LocalServiceReadOnly ||
        !result.AuditPolicy.SuccessEnabled ||
        result.AuditPolicy.FailureEnabled ||
        result.Targets.Count != 3 ||
        result.Targets.Any(target =>
            !target.Exists ||
            !target.ZeroLength ||
            target.ReparsePoint ||
            !target.SaclAccessible ||
            !target.ExactSuccessAudit ||
            target.ErrorCode is not null) ||
        probe.ChannelCalls != 1 ||
        probe.AuditPolicyCalls != 1 ||
        probe.TargetCalls != 3)
    {
        throw new InvalidOperationException(
            "SENSOR_C2D_SECURITY_4663_READINESS_CHECK_INVALID");
    }
}

static void RejectsSecurity4663ReadinessCheckDrift()
{
    var failedProbes = new[]
    {
        FakeSecurity4663ReadinessProbe.Ready() with
        {
            Channel = new(false, false, "access-denied")
        },
        FakeSecurity4663ReadinessProbe.Ready() with
        {
            AuditPolicy = new(true, false, false, null)
        },
        FakeSecurity4663ReadinessProbe.Ready() with
        {
            TargetFactory = target => new(
                target.ProfileId,
                true,
                true,
                true,
                true,
                true,
                null)
        },
        FakeSecurity4663ReadinessProbe.Ready() with
        {
            TargetFactory = target => new(
                target.ProfileId,
                true,
                true,
                false,
                false,
                false,
                "sacl-access-denied")
        }
    };
    foreach (var probe in failedProbes)
    {
        var result = Security4663ReadinessCheck.Check(probe);
        if (
            result.Ready ||
            result.ReadsEvents ||
            result.EventsRead != 0 ||
            result.RuntimeCollectionEnabled ||
            result.TransportEnabled ||
            result.CommandChannelEnabled)
        {
            throw new InvalidOperationException(
                "SENSOR_C2D_SECURITY_4663_READINESS_CHECK_FAIL_OPEN");
        }
    }
}

static void ValidatesSecurity4663CeremonyPlan()
{
    var plan = Security4663ReadinessCeremony.BuildPlan();
    Security4663ReadinessCeremony.ValidatePlan(plan);
    if (
        plan.SchemaVersion != 1 ||
        plan.Checkpoint != "gate-c2d-security-4663-machine-readiness" ||
        plan.StatePath != @"C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-ceremony-state.json" ||
        !plan.RequiresElevation ||
        !plan.TemporarilyEnablesOperatorSecurityPrivilege ||
        plan.AssignsPrivilegeToService ||
        !plan.RequiresExactLocalServiceIdentity ||
        !plan.RequiresFixtureRootAbsent ||
        !plan.PreservesOriginalChannelDescriptor ||
        !plan.PreservesOriginalAuditPolicy ||
        !plan.AppliesLocalServiceReadOnlyChannelAce ||
        !plan.AppliesAuditSuccessOnly ||
        !plan.CreatesOnlyFixedInertTargets ||
        !plan.RollbackRequired ||
        plan.ReadsEvents ||
        plan.EventsRead != 0 ||
        plan.RuntimeCollectionEnabled ||
        plan.TransportEnabled ||
        plan.InboundListenerEnabled ||
        plan.CommandChannelEnabled ||
        WindowsEventSourceReadinessCommandParser.Parse(
            ["security-4663-ceremony-plan"]) !=
                WindowsEventSourceReadinessCommand.Security4663CeremonyPlan ||
        WindowsEventSourceReadinessCommandParser.Parse(
            ["security-4663-apply"]) !=
                WindowsEventSourceReadinessCommand.Security4663Apply ||
        WindowsEventSourceReadinessCommandParser.Parse(
            ["security-4663-rollback"]) !=
                WindowsEventSourceReadinessCommand.Security4663Rollback ||
        WindowsEventSourceReadinessCommandParser.Parse(
            ["security-4663-exercise"]) !=
                WindowsEventSourceReadinessCommand.Security4663Exercise)
    {
        throw new InvalidOperationException(
            "SENSOR_C2D_SECURITY_4663_CEREMONY_PLAN_INVALID");
    }

    var snapshot = Security4663ReadinessCeremony.CreateSnapshot(
        "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)",
        3);
    Security4663ReadinessCeremony.ValidateSnapshot(snapshot);
    ExpectInvalidData(
        () => Security4663ReadinessCeremony.ValidateSnapshot(
            snapshot with { OriginalAuditPolicy = 1 }),
        "SENSOR_C2D_SECURITY_4663_STATE_INVALID");
}

static void ValidatesSecurity4663CeremonyApply()
{
    var store = new FakeSecurity4663CeremonyStore();
    var result = Security4663ReadinessCeremony.Apply(store);
    if (
        !result.Completed ||
        result.Operation != "apply" ||
        !result.ServiceIdentityValidated ||
        !result.OriginalStateProtected ||
        !result.ChannelChanged ||
        !result.AuditPolicyChanged ||
        !result.TargetSaclChanged ||
        result.OriginalStateRestored ||
        result.ReadsEvents ||
        result.EventsRead != 0 ||
        result.RuntimeCollectionEnabled ||
        result.TransportEnabled ||
        result.CommandChannelEnabled ||
        string.Join(',', store.Calls) !=
            "admin,identity,preconditions,capture,write-state,channel,audit,targets,check")
    {
        throw new InvalidOperationException(
            "SENSOR_C2D_SECURITY_4663_CEREMONY_APPLY_INVALID");
    }
}

static void ValidatesSecurity4663CeremonyRecovery()
{
    var store = new FakeSecurity4663CeremonyStore("audit");
    ExpectInvalidData(
        () => Security4663ReadinessCeremony.Apply(store),
        "test-failure-audit");
    if (string.Join(',', store.Calls) !=
        "admin,identity,preconditions,capture,write-state,channel,audit,recover")
    {
        throw new InvalidOperationException(
            "SENSOR_C2D_SECURITY_4663_CEREMONY_RECOVERY_INVALID");
    }
}

static void ValidatesSecurity4663CeremonyRollback()
{
    var store = new FakeSecurity4663CeremonyStore();
    var result = Security4663ReadinessCeremony.Rollback(store);
    if (
        !result.Completed ||
        result.Operation != "rollback" ||
        result.ChannelChanged ||
        result.AuditPolicyChanged ||
        result.TargetSaclChanged ||
        !result.OriginalStateRestored ||
        result.ReadsEvents ||
        result.EventsRead != 0 ||
        string.Join(',', store.Calls) !=
            "admin,identity,read-state,rollback-preconditions,restore,remove")
    {
        throw new InvalidOperationException(
            "SENSOR_C2D_SECURITY_4663_CEREMONY_ROLLBACK_INVALID");
    }
}

static void ValidatesSecurity4663CeremonyExercise()
{
    var store = new FakeSecurity4663CeremonyStore();
    var result = Security4663ReadinessCeremony.Exercise(store);
    if (
        !result.Completed ||
        !result.Applied ||
        !result.ReadyBeforeRollback ||
        !result.OriginalStateRestored ||
        result.ReadsEvents ||
        result.EventsRead != 0 ||
        result.RuntimeCollectionEnabled ||
        result.TransportEnabled ||
        result.InboundListenerEnabled ||
        result.CommandChannelEnabled ||
        string.Join(',', store.Calls) !=
            "admin,identity,preconditions,capture,write-state,channel,audit,targets,check,admin,identity,read-state,rollback-preconditions,restore,remove")
    {
        throw new InvalidOperationException(
            "SENSOR_C2D_SECURITY_4663_CEREMONY_EXERCISE_INVALID");
    }
}

static void ValidatesSecurity4663AuditRestoreMapping()
{
    var cases = new (uint Captured, uint Behavior, uint Settable)[]
    {
        (0, 0, 4),
        (1, 1, 1),
        (2, 2, 2),
        (3, 3, 3),
        (4, 0, 4),
        (5, 1, 1),
        (6, 2, 2),
        (7, 3, 3)
    };
    foreach (var item in cases)
    {
        if (
            NativeSecurity4663CeremonyStore.CanonicalAuditBehavior(
                item.Captured) != item.Behavior ||
            NativeSecurity4663CeremonyStore.ToSettableAuditPolicy(
                item.Captured) != item.Settable)
        {
            throw new InvalidOperationException(
                "SENSOR_C2D_SECURITY_4663_AUDIT_RESTORE_MAPPING_INVALID");
        }
    }
}

static void ChecksExactSourceMetadata()
{
    var reader = new FakeWindowsEventLogMetadataReader(
        source =>
            source switch
            {
                WindowsEventLogSource.System =>
                    new WindowsEventLogMetadata(true, 10),
                WindowsEventLogSource.Application =>
                    new WindowsEventLogMetadata(true, 20),
                _ => throw new InvalidOperationException(
                    "an arbitrary event channel was requested")
            });
    var result = WindowsEventSourceReadiness.Check(reader);
    if (
        !result.Ready ||
        result.ServiceIdentityValidated ||
        result.RuntimeCollectionEnabled ||
        result.TransportEnabled ||
        result.InboundListenerEnabled ||
        result.CommandChannelEnabled ||
        result.ArbitraryChannelsAllowed ||
        result.RawEventContentRead ||
        result.EventsRead != 0 ||
        !reader.Requested.SequenceEqual(
            new[]
            {
                WindowsEventLogSource.System,
                WindowsEventLogSource.Application
            }) ||
        result.Sources.Any(
            source =>
                !source.Accessible ||
                !source.Enabled ||
                source.RecordCount is null or < 0 ||
                source.ErrorCode is not null))
    {
        throw new InvalidOperationException(
            "source readiness exceeded or failed its metadata-only boundary");
    }
}

static void RejectsUnavailableSourceMetadata()
{
    var reader = new FakeWindowsEventLogMetadataReader(
        source =>
        {
            if (source == WindowsEventLogSource.Application)
            {
                throw new UnauthorizedAccessException();
            }
            return new WindowsEventLogMetadata(true, 10);
        });
    var result = WindowsEventSourceReadiness.Check(reader);
    var denied = result.Sources.Single(
        source => source.SourceId == "windows-application");
    if (
        result.Ready ||
        denied.Accessible ||
        denied.Enabled ||
        denied.RecordCount is not null ||
        denied.ErrorCode != "access-denied" ||
        result.RawEventContentRead ||
        result.EventsRead != 0)
    {
        throw new InvalidOperationException(
            "unavailable source metadata did not fail closed");
    }
}

static void ValidatesSecurity4663ApprovalConsumeProofPlan()
{
    var plan = Security4663OneShotApprovalConsumeProof.BuildPlan();
    Security4663OneShotApprovalConsumeProof.ValidatePlan(plan);
    if (
        plan.SchemaVersion != 1 ||
        plan.Checkpoint != Security4663OneShotMachinePlan.Checkpoint ||
        plan.StartupArgument != "--security-4663-one-shot" ||
        plan.StartupModeRegistryPath !=
            @"SYSTEM\CurrentControlSet\Services\WARRoomWindowsSensor\Parameters" ||
        plan.StartupModeRegistryValueName != "StartupMode" ||
        plan.ServiceIdentity != @"NT AUTHORITY\LocalService" ||
        !plan.RequiresLocalServiceBeforeProtectedRead ||
        !plan.ConsumesApprovalExactlyOnce ||
        plan.WritesResult ||
        plan.MaximumEventsRead != 0 ||
        plan.RawEventContentRead ||
        plan.EventReaderEnabled ||
        plan.RetryEnabled ||
        plan.PollingEnabled ||
        plan.TransportEnabled ||
        plan.InboundListenerEnabled ||
        plan.CommandChannelEnabled ||
        plan.ResponseActionEnabled ||
        plan.ChangesServiceImagePath ||
        !plan.RequiresStartupModeRollback ||
        plan.NormalStartupEnabled ||
        !plan.GuardedOperatorInvocationWired ||
        !Security4663OneShotApprovalConsumeProof.RuntimeWired)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_CONSUME_PROOF_PLAN_INVALID");
    }
    ExpectInvalidData(
        () => Security4663OneShotApprovalConsumeProof.ValidatePlan(
            plan with { EventReaderEnabled = true }),
        "SENSOR_C2E_SECURITY_4663_CONSUME_PROOF_PLAN_INVALID");
}

static void ValidatesSecurity4663ApprovalConsumeProof()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTime(2026, 8, 9, 13, 0, 0, DateTimeKind.Utc);
    using var identity = new FakeSensorIdentitySigner();
    var store = new FakeSecurity4663OneShotApprovalStore();
    _ = Security4663OneShotApprovalLifecycle.CreateAndWrite(
        store,
        identity,
        commit,
        42,
        now,
        Security4663ApprovalNonce());
    var manifest = new FakeInstallManifestBindingReader(new(
        commit,
        identity.Descriptor.CertificateFingerprintSha256,
        new string('b', 64)));
    var result = Security4663OneShotApprovalConsumeProof.Consume(
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        manifest,
        store,
        identity,
        new FixedTestTimeProvider(now.AddSeconds(30)),
        CancellationToken.None);
    if (
        result.State != "consumed" ||
        result.BaselineRecordId != 42 ||
        !result.LocalServiceIdentityValidated ||
        !result.ApprovalConsumed ||
        result.EventsRead != 0 ||
        result.RawEventContentRead ||
        result.EventReaderEnabled ||
        result.RetryEnabled ||
        result.PollingEnabled ||
        result.TransportEnabled ||
        result.InboundListenerEnabled ||
        result.CommandChannelEnabled ||
        result.ResponseActionEnabled ||
        manifest.ReadCount != 1 ||
        store.ConsumeCount != 1 ||
        store.Document is not null)
    {
        throw new InvalidOperationException(
            "SENSOR_C2E_SECURITY_4663_CONSUME_PROOF_RESULT_INVALID");
    }
}

static void RejectsSecurity4663ApprovalConsumeProofDrift()
{
    const string commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var now = new DateTime(2026, 8, 9, 13, 0, 0, DateTimeKind.Utc);
    using var identity = new FakeSensorIdentitySigner();
    var store = new FakeSecurity4663OneShotApprovalStore
    {
        Document = "must-not-be-read"
    };
    var manifest = new FakeInstallManifestBindingReader(new(
        commit,
        identity.Descriptor.CertificateFingerprintSha256,
        new string('b', 64)));
    try
    {
        _ = Security4663OneShotApprovalConsumeProof.Consume(
            new FakeSensorServiceIdentity("S-1-5-21-1000"),
            manifest,
            store,
            identity,
            new FixedTestTimeProvider(now),
            CancellationToken.None);
    }
    catch (InvalidOperationException error) when (
        error.Message == "SENSOR_LOCALSERVICE_IDENTITY_REQUIRED" &&
        manifest.ReadCount == 0 &&
        store.ReadCount == 0 &&
        store.ConsumeCount == 0)
    {
        var driftedManifest = new FakeInstallManifestBindingReader(new(
            commit,
            new string('c', 64),
            new string('b', 64)));
        ExpectInvalidData(
            () => Security4663OneShotApprovalConsumeProof.Consume(
                new FakeSensorServiceIdentity(
                    NativeKeyAccessPolicy.LocalServiceSid),
                driftedManifest,
                store,
                identity,
                new FixedTestTimeProvider(now),
                CancellationToken.None),
            "SENSOR_C2E_SECURITY_4663_CONSUME_PROOF_CONTEXT_INVALID");
        if (
            driftedManifest.ReadCount != 1 ||
            store.ReadCount != 0 ||
            store.ConsumeCount != 0)
        {
            throw new InvalidOperationException(
                "consume-proof context drift reached approval access");
        }
        return;
    }
    throw new InvalidOperationException(
        "consume proof reached protected state before LocalService validation");
}

static void ValidatesServiceStartupArguments()
{
    if (
        SensorStartupArguments.Parse(Array.Empty<string>()) !=
            SensorStartupMode.Normal ||
        SensorStartupArguments.Parse(["--security-4663-one-shot"]) !=
            SensorStartupMode.Security4663ApprovalConsumeProof ||
        SensorStartupArguments.Parse(["--security-4663-live-one-shot"]) !=
            SensorStartupMode.Security4663LiveOneShot ||
        SensorStartupArguments.Resolve(
            Array.Empty<string>(),
            new FakeSensorStartupModeSource(null)) !=
                SensorStartupMode.Normal ||
        SensorStartupArguments.Resolve(
            Array.Empty<string>(),
            new FakeSensorStartupModeSource("--security-4663-one-shot")) !=
                SensorStartupMode.Security4663ApprovalConsumeProof ||
        SensorStartupArguments.Resolve(
            Array.Empty<string>(),
            new FakeSensorStartupModeSource("--security-4663-live-one-shot")) !=
                SensorStartupMode.Security4663LiveOneShot)
    {
        throw new InvalidOperationException(
            "exact service startup mode was rejected");
    }
    ExpectInvalidData(
        () => SensorStartupArguments.Resolve(
            Array.Empty<string>(),
            new FakeSensorStartupModeSource("--collect")),
        "SENSOR_STARTUP_MODE_INVALID");
    foreach (var arguments in new[]
    {
        new[] { "--collect" },
        new[] { "--security-4663-one-shot", "extra" },
        new[] { "--security-4663-one-shot=1" },
        new[] { "--SECURITY-4663-ONE-SHOT" },
        new[] { "--security-4663-live-one-shot", "extra" },
        new[] { "--security-4663-live-one-shot=1" },
        new[] { "--SECURITY-4663-LIVE-ONE-SHOT" },
        new[] { "--localservice-gate-a-readiness" },
        new[] { "--localservice-gate-a-readiness", "System" },
        new[] { "--localservice-gate-a-readiness=Security" }
    })
    {
        try
        {
            SensorStartupArguments.Validate(arguments);
        }
        catch (InvalidDataException error) when (
            error.Message == "SENSOR_STARTUP_ARGUMENTS_DENIED")
        {
            continue;
        }
        throw new InvalidOperationException(
            "alternate service startup argument was accepted");
    }
}

static void ValidatesLocalServiceGateAReadiness()
{
    var reader = new FakeWindowsEventLogMetadataReader(
        source => source switch
        {
            WindowsEventLogSource.System => new WindowsEventLogMetadata(true, 10),
            WindowsEventLogSource.Application => new WindowsEventLogMetadata(true, 20),
            _ => throw new InvalidOperationException("an arbitrary log was requested")
        });
    var result = LocalServiceGateAReadiness.Validate(
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        reader);
    if (
        !result.Ready ||
        result.EventsRead != 0 ||
        result.RawEventContentRead ||
        !reader.Requested.SequenceEqual(
            new[]
            {
                WindowsEventLogSource.System,
                WindowsEventLogSource.Application
            }))
    {
        throw new InvalidOperationException(
            "LocalService Gate A did not retain its metadata-only boundary");
    }
}

static void RejectsLocalServiceGateAReadiness()
{
    var wrongIdentityReader = new FakeWindowsEventLogMetadataReader(
        _ => throw new InvalidOperationException("event metadata should not be read"));
    try
    {
        LocalServiceGateAReadiness.Validate(
            new FakeSensorServiceIdentity("S-1-5-21-1000"),
            wrongIdentityReader);
    }
    catch (InvalidOperationException error) when (
        error.Message == "SENSOR_LOCALSERVICE_IDENTITY_REQUIRED" &&
        wrongIdentityReader.Requested.Count == 0)
    {
        var deniedReader = new FakeWindowsEventLogMetadataReader(
            source =>
            {
                if (source == WindowsEventLogSource.Application)
                {
                    throw new UnauthorizedAccessException();
                }
                return new WindowsEventLogMetadata(true, 10);
            });
        try
        {
            LocalServiceGateAReadiness.Validate(
                new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
                deniedReader);
        }
        catch (InvalidOperationException unavailable) when (
            unavailable.Message == "SENSOR_LOCALSERVICE_GATE_A_UNAVAILABLE" &&
            deniedReader.Requested.SequenceEqual(
                new[]
                {
                    WindowsEventLogSource.System,
                    WindowsEventLogSource.Application
                }))
        {
            return;
        }
    }
    throw new InvalidOperationException(
        "LocalService Gate A did not fail closed");
}

static void KeepsControlPlaneAbsent()
{
    if (
        SensorBoundary.PermitsInboundListener ||
        SensorBoundary.PermitsCommandChannel ||
        SensorBoundary.PermitsJobPolling ||
        SensorBoundary.PermitsResponseActions)
    {
        throw new InvalidOperationException("a sensor control-plane capability is enabled");
    }
}

static void ValidatesBoundedCollectorContract()
{
    var contracts = BoundedMultiEventCollector.Contracts;
    if (
        BoundedMultiEventCollector.MaximumFamilies != 2 ||
        BoundedMultiEventCollector.MaximumRecordsPerFamily != 1 ||
        BoundedMultiEventCollector.MaximumEvents != 2 ||
        BoundedMultiEventCollector.MaximumReadMillisecondsPerFamily != 2_000 ||
        BoundedMultiEventCollector.MaximumTotalReadMilliseconds != 4_000 ||
        BoundedMultiEventCollector.AllowedRecordAccessors.Count != 5 ||
        string.Join(",", BoundedMultiEventCollector.AllowedRecordAccessors) !=
            "Id,Level,ProviderName,RecordId,TimeCreated" ||
        contracts.Count != 2 ||
        contracts[0] != new BoundedEventFamilyContract(
            BoundedEventFamily.ScmServiceInstalled,
            "System",
            "Service Control Manager",
            7045,
            4,
            "*[System[Provider[@Name='Service Control Manager'] and EventID=7045 and Level=4]]",
            "windows-scm",
            "system",
            "service-change",
            new BoundedFactMapping(
                "unknown", "create", "other", "service", "unknown")) ||
        contracts[1] != new BoundedEventFamilyContract(
            BoundedEventFamily.ScmServiceStateChanged,
            "System",
            "Service Control Manager",
            7036,
            4,
            "*[System[Provider[@Name='Service Control Manager'] and EventID=7036 and Level=4]]",
            "windows-scm",
            "system",
            "service-state-change",
            new BoundedFactMapping(
                "unknown", "modify", "other", "service", "unknown")))
    {
        throw new InvalidOperationException("SENSOR_C1_SOURCE_CONTRACT_DRIFT");
    }
}

static void ValidatesBoundedCollectorCoordinator()
{
    var occurredAt = new DateTimeOffset(
        2026, 8, 8, 10, 0, 0, TimeSpan.Zero);
    var reader = new FakeBoundedEventMetadataReader(family =>
        family == BoundedEventFamily.ScmServiceInstalled
            ? new BoundedEventReadResult(
                BoundedEventReadState.Match,
                new BoundedEventMetadata(
                    "Service Control Manager", 7045, 4, occurredAt, 100))
            : new BoundedEventReadResult(
                BoundedEventReadState.NoMatch,
                null));
    var snapshot = new BoundedMultiEventCollector(reader)
        .CollectOnce(occurredAt.UtcDateTime, CancellationToken.None);
    if (
        reader.Requested.Count != 2 ||
        reader.Requested[0] != BoundedEventFamily.ScmServiceInstalled ||
        reader.Requested[1] != BoundedEventFamily.ScmServiceStateChanged ||
        snapshot.CollectionMode != "explicit-one-shot-contract" ||
        snapshot.LossState != "unknown" ||
        snapshot.ContinuityState != "unknown" ||
        snapshot.FamiliesQueried != 2 ||
        snapshot.EventsRead != 1 ||
        snapshot.Results.Count != 2 ||
        snapshot.RawEventContentRead ||
        snapshot.RuntimeWired ||
        snapshot.NetworkTransportEnabled ||
        snapshot.AutomaticRetryEnabled ||
        snapshot.PollingEnabled ||
        snapshot.InboundListenerEnabled ||
        snapshot.CommandChannelEnabled ||
        snapshot.ResponseActionsEnabled)
    {
        throw new InvalidOperationException("SENSOR_C1_COORDINATOR_INVALID");
    }

    var stale = new BoundedMultiEventCollector(
        new FakeBoundedEventMetadataReader(family =>
            family == BoundedEventFamily.ScmServiceStateChanged
                ? new BoundedEventReadResult(
                    BoundedEventReadState.Match,
                    new BoundedEventMetadata(
                        "Service Control Manager",
                        7036,
                        4,
                        occurredAt.AddTicks(-1),
                        99))
                : new BoundedEventReadResult(
                    BoundedEventReadState.NoMatch,
                    null)))
        .CollectOnce(occurredAt.UtcDateTime, CancellationToken.None);
    if (
        stale.EventsRead != 0 ||
        stale.Results[1].State != BoundedEventReadState.NoMatch ||
        stale.Results[1].Metadata is not null)
    {
        throw new InvalidOperationException(
            "SENSOR_C1_STALE_EVENT_NORMALIZATION_INVALID");
    }
}

static void RejectsBoundedCollectorDrift()
{
    var wrongMetadata = new FakeBoundedEventMetadataReader(_ =>
        new BoundedEventReadResult(
            BoundedEventReadState.Match,
            new BoundedEventMetadata(
                "Service Control Manager",
                4624,
                4,
                new DateTimeOffset(2026, 8, 8, 10, 0, 0, TimeSpan.Zero),
                1)));
    AssertThrows<InvalidDataException>(
        () => new BoundedMultiEventCollector(wrongMetadata)
            .CollectOnce(
                new DateTime(2026, 8, 8, 9, 0, 0, DateTimeKind.Utc),
                CancellationToken.None),
        "SENSOR_C1_EVENT_METADATA_INVALID");

    var malformedStale = new FakeBoundedEventMetadataReader(_ =>
        new BoundedEventReadResult(
            BoundedEventReadState.Match,
            new BoundedEventMetadata(
                "wrong provider",
                7045,
                4,
                new DateTimeOffset(2026, 8, 8, 8, 0, 0, TimeSpan.Zero),
                1)));
    AssertThrows<InvalidDataException>(
        () => new BoundedMultiEventCollector(malformedStale)
            .CollectOnce(
                new DateTime(2026, 8, 8, 9, 0, 0, DateTimeKind.Utc),
                CancellationToken.None),
        "SENSOR_C1_EVENT_METADATA_INVALID");

    var leakedMetadata = new FakeBoundedEventMetadataReader(_ =>
        new BoundedEventReadResult(
            BoundedEventReadState.AccessDenied,
            new BoundedEventMetadata(
                "Service Control Manager",
                7045,
                4,
                new DateTimeOffset(2026, 8, 8, 10, 0, 0, TimeSpan.Zero),
                1)));
    AssertThrows<InvalidDataException>(
        () => new BoundedMultiEventCollector(leakedMetadata)
            .CollectOnce(
                new DateTime(2026, 8, 8, 9, 0, 0, DateTimeKind.Utc),
                CancellationToken.None),
        "SENSOR_C1_NONMATCH_METADATA_INVALID");

    using var cancelled = new CancellationTokenSource();
    cancelled.Cancel();
    AssertThrows<OperationCanceledException>(
        () => new BoundedMultiEventCollector(
            new FakeBoundedEventMetadataReader(_ =>
                new BoundedEventReadResult(
                    BoundedEventReadState.NoMatch,
                    null))).CollectOnce(
                        new DateTime(2026, 8, 8, 9, 0, 0, DateTimeKind.Utc),
                        cancelled.Token));
}

static void ValidatesNativeBoundedReaderSelection()
{
    var boundary = new DateTime(2026, 8, 8, 10, 0, 0, DateTimeKind.Utc);
    var stale = BoundedMultiEventCollector.ApplyCollectionWindow(
        new BoundedEventReadResult(
            BoundedEventReadState.Match,
            new BoundedEventMetadata(
                "Service Control Manager",
                7036,
                4,
                new DateTimeOffset(boundary.AddTicks(-1)),
                1)),
        boundary);
    var exact = BoundedMultiEventCollector.ApplyCollectionWindow(
        new BoundedEventReadResult(
            BoundedEventReadState.Match,
            new BoundedEventMetadata(
                "Service Control Manager",
                7036,
                4,
                new DateTimeOffset(boundary),
                2)),
        boundary);
    if (
        stale.State != BoundedEventReadState.NoMatch ||
        stale.Metadata is not null ||
        exact.State != BoundedEventReadState.Match ||
        exact.Metadata is null ||
        NativeBoundedEventMetadataReader.ContractFor(
            BoundedEventFamily.ScmServiceInstalled) !=
            BoundedMultiEventCollector.Contracts[0] ||
        NativeBoundedEventMetadataReader.ContractFor(
            BoundedEventFamily.ScmServiceStateChanged) !=
            BoundedMultiEventCollector.Contracts[1])
    {
        throw new InvalidOperationException("SENSOR_C1_NATIVE_QUERY_DRIFT");
    }
    AssertThrows<InvalidOperationException>(
        () => NativeBoundedEventMetadataReader.ContractFor(
            (BoundedEventFamily)3),
        "SENSOR_C1_EVENT_FAMILY_INVALID");
    AssertThrows<InvalidOperationException>(
        () => BoundedMultiEventCollector.ApplyCollectionWindow(
            exact,
            DateTime.SpecifyKind(boundary, DateTimeKind.Local)),
        "SENSOR_C1_COLLECTION_WINDOW_INVALID");
}

static BoundedCollectorSnapshot BoundedCollectorFixture(
    DateTimeOffset occurredAt,
    BoundedEventReadState secondState = BoundedEventReadState.AccessDenied,
    FakeBoundedEventMetadataReader? suppliedReader = null)
{
    var reader = suppliedReader ?? new FakeBoundedEventMetadataReader(family =>
        family == BoundedEventFamily.ScmServiceInstalled
            ? new BoundedEventReadResult(
                BoundedEventReadState.Match,
                new BoundedEventMetadata(
                    "Service Control Manager", 7045, 4, occurredAt, 200))
            : new BoundedEventReadResult(secondState, null));
    return new BoundedMultiEventCollector(reader)
        .CollectOnce(occurredAt.UtcDateTime, CancellationToken.None);
}

static void ValidatesBoundedCollectorProof()
{
    using var identity = new FakeSensorIdentitySigner();
    var manifest = new DateTime(2026, 8, 8, 10, 0, 0, DateTimeKind.Utc);
    var generated = manifest.AddSeconds(10);
    var proof = BoundedCollectorProof.Create(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        BoundedCollectorFixture(new DateTimeOffset(manifest.AddSeconds(5))),
        Enumerable.Range(0, BoundedCollectorProof.SaltBytes)
            .Select(value => (byte)value)
            .ToArray(),
        manifest,
        generated);
    var validation = BoundedCollectorProof.ValidateForManifest(
        BoundedCollectorProof.Serialize(proof),
        identity,
        manifest);
    if (
        validation.FamiliesQueried != 2 ||
        validation.EventsRead != 1 ||
        validation.MatchCount != 1 ||
        validation.NoMatchCount != 0 ||
        validation.FailureCount != 1 ||
        validation.ProofHash.Length != 64 ||
        validation.RawEventContentRead ||
        !validation.RuntimeProofEventReaderEnabled ||
        validation.NetworkTransportEnabled ||
        validation.AutomaticRetryEnabled ||
        validation.PollingEnabled ||
        validation.InboundListenerEnabled ||
        validation.CommandChannelEnabled ||
        validation.ResponseActionsEnabled)
    {
        throw new InvalidOperationException("SENSOR_C1_PROOF_VALIDATION_INVALID");
    }
    var json = BoundedCollectorProof.Serialize(proof);
    if (json.Contains("\"recordId\"", StringComparison.Ordinal) ||
        json.Contains("\"sourceSalt\"", StringComparison.Ordinal))
    {
        throw new InvalidOperationException("SENSOR_C1_PROOF_PRIVACY_INVALID");
    }
}

static void RejectsBoundedCollectorProofDrift()
{
    using var identity = new FakeSensorIdentitySigner();
    var manifest = new DateTime(2026, 8, 8, 10, 0, 0, DateTimeKind.Utc);
    var salt = Enumerable.Repeat((byte)0x5a, BoundedCollectorProof.SaltBytes)
        .ToArray();
    var proof = BoundedCollectorProof.Create(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        BoundedCollectorFixture(new DateTimeOffset(manifest.AddSeconds(1))),
        salt,
        manifest,
        manifest.AddSeconds(2));
    var tampered = proof with { ProofHash = new string('0', 64) };
    AssertThrows<InvalidDataException>(
        () => BoundedCollectorProof.Validate(
            BoundedCollectorProof.Serialize(tampered),
            identity),
        "SENSOR_C1_PROOF_SIGNATURE_INVALID");
    AssertThrows<InvalidDataException>(
        () => BoundedCollectorProof.ValidateForManifest(
            BoundedCollectorProof.Serialize(proof),
            identity,
            manifest.AddSeconds(1)),
        "SENSOR_C1_PROOF_MANIFEST_MISMATCH");
    AssertThrows<InvalidDataException>(
        () => BoundedCollectorProof.Create(
            identity,
            new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
            BoundedCollectorFixture(new DateTimeOffset(manifest.AddSeconds(-1))),
            salt,
            manifest,
            manifest.AddSeconds(2)),
        "SENSOR_C1_PROOF_MATCH_METADATA_INVALID");
}

static void ValidatesBoundedCollectorProofWorker()
{
    using var identity = new FakeSensorIdentitySigner();
    var manifest = new DateTime(2026, 8, 8, 10, 0, 0, DateTimeKind.Utc);
    var reader = new FakeBoundedEventMetadataReader(family =>
        family == BoundedEventFamily.ScmServiceInstalled
            ? new BoundedEventReadResult(
                BoundedEventReadState.Match,
                new BoundedEventMetadata(
                    "Service Control Manager",
                    7045,
                    4,
                    new DateTimeOffset(manifest.AddSeconds(1)),
                    201))
            : new BoundedEventReadResult(BoundedEventReadState.NoMatch, null));
    var store = new FakeBoundedCollectorProofStore(
        Enumerable.Repeat((byte)0x33, BoundedCollectorProof.SaltBytes).ToArray());
    var worker = new BoundedCollectorProofWorker(
        identity,
        new FakeSensorServiceIdentity(NativeKeyAccessPolicy.LocalServiceSid),
        new BoundedMultiEventCollector(reader),
        store,
        new FakeManifestTimestampReader(manifest),
        new FixedTestTimeProvider(manifest.AddSeconds(2)),
        NullLogger<BoundedCollectorProofWorker>.Instance);
    worker.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
    worker.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
    if (reader.Requested.Count != 2 || store.WriteCount != 1 ||
        store.Document is null)
    {
        throw new InvalidOperationException("SENSOR_C1_PROOF_ONE_SHOT_INVALID");
    }
}

static InertWindowsSecurityEventRecord InertSecurity1102Fixture() =>
    new(
        "Microsoft-Windows-Eventlog",
        "Security",
        1102,
        4,
        new DateTimeOffset(2026, 8, 9, 9, 0, 0, TimeSpan.Zero),
        42,
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["SubjectUserSid"] = "S-1-5-21-1000",
            ["SubjectUserName"] = "inert-operator",
            ["SubjectDomainName"] = "INERT-LAB",
            ["SubjectLogonId"] = "0x1234"
        });

static void ValidatesInertSecurity1102Parser()
{
    var fact = InertWindowsSecurityEvent1102Parser.Parse(
        InertSecurity1102Fixture());
    if (
        InertWindowsSecurityEvent1102Parser.RuntimeWired ||
        InertWindowsSecurityEvent1102Parser.AllowedEventDataFields.Count != 4 ||
        fact.Provider != "windows-security" ||
        fact.Channel != "security" ||
        fact.EventFamily != "event-log-clear" ||
        fact.OccurredAtUtc.Offset != TimeSpan.Zero ||
        fact.SourceRecordId != 42 ||
        fact.Mapping != new BoundedFactMapping(
            "unknown", "clear", "other", "event-log", "success") ||
        fact.RawEventContentRetained)
    {
        throw new InvalidOperationException("SENSOR_C2C_EVENT_1102_MAPPING_INVALID");
    }

    var output = JsonSerializer.Serialize(fact);
    if (
        output.Contains("inert-operator", StringComparison.Ordinal) ||
        output.Contains("INERT-LAB", StringComparison.Ordinal) ||
        output.Contains("S-1-5-21-1000", StringComparison.Ordinal) ||
        output.Contains("0x1234", StringComparison.Ordinal))
    {
        throw new InvalidOperationException("SENSOR_C2C_EVENT_1102_RAW_LEAK");
    }
}

static void RejectsInertSecurity1102ParserDrift()
{
    var fixture = InertSecurity1102Fixture();
    var metadataDrift = new[]
    {
        fixture with { ProviderName = "Microsoft-Windows-Security-Auditing" },
        fixture with { ChannelName = "System" },
        fixture with { EventId = 104 },
        fixture with { Level = 0 },
        fixture with { TimeCreatedUtc = fixture.TimeCreatedUtc.ToOffset(TimeSpan.FromHours(1)) },
        fixture with { RecordId = 0 }
    };
    foreach (var candidate in metadataDrift)
    {
        AssertThrows<InvalidDataException>(
            () => InertWindowsSecurityEvent1102Parser.Parse(candidate),
            "SENSOR_C2C_EVENT_1102_METADATA_INVALID");
    }

    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurityEvent1102Parser.Parse(
            fixture with
            {
                EventData = fixture.EventData
                    .Where(pair => pair.Key != "SubjectLogonId")
                    .ToDictionary(pair => pair.Key, pair => pair.Value)
            }),
        "SENSOR_C2C_EVENT_1102_FIELDS_INVALID");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurityEvent1102Parser.Parse(
            fixture with
            {
                EventData = new Dictionary<string, string>(fixture.EventData)
                {
                    ["Message"] = "raw content"
                }
            }),
        "SENSOR_C2C_EVENT_1102_FIELDS_INVALID");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurityEvent1102Parser.Parse(
            fixture with
            {
                EventData = new Dictionary<string, string>(fixture.EventData)
                {
                    ["SubjectUserSid"] = "not-a-sid"
                }
            }),
        "SENSOR_C2C_EVENT_1102_VALUES_INVALID");
}

static InertWindowsSecurityEventRecord InertSecurity4663Fixture(
    string accessList = "%%4416",
    string accessMask = "0x1") =>
    new(
        "Microsoft-Windows-Security-Auditing",
        "Security",
        4663,
        0,
        new DateTimeOffset(2026, 8, 9, 10, 0, 0, TimeSpan.Zero),
        43,
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["SubjectUserSid"] = "S-1-5-21-2000",
            ["SubjectUserName"] = "inert-subject",
            ["SubjectDomainName"] = "INERT-LAB",
            ["SubjectLogonId"] = "0x2234",
            ["ObjectServer"] = "Security",
            ["ObjectType"] = "File",
            ["ObjectName"] = @"C:\Inert\classified-target.bin",
            ["HandleId"] = "0x10",
            ["AccessList"] = accessList,
            ["AccessMask"] = accessMask,
            ["ProcessId"] = "0x458",
            ["ProcessName"] = @"C:\Inert\fixture-process.exe",
            ["ResourceAttributes"] = "-"
        });

static void ValidatesInertSecurity4663Profiles()
{
    var credential = InertWindowsSecurityEvent4663Parser.ParseCandidate(
        InertSecurity4663Fixture(),
        InertWindowsSecurityEvent4663Profile.CredentialStoreRead);
    var secret = InertWindowsSecurityEvent4663Parser.ParseCandidate(
        InertSecurity4663Fixture(),
        InertWindowsSecurityEvent4663Profile.UnsecuredSecretRead);
    var hidden = InertWindowsSecurityEvent4663Parser.ParseCandidate(
        InertSecurity4663Fixture("%%4424", "0x100"),
        InertWindowsSecurityEvent4663Profile.HiddenAttributeWrite);
    var nativeWindows = InertWindowsSecurityEvent4663Parser.ParseCandidate(
        InertSecurity4663Fixture("%%4416\n\t\t\t\t"),
        InertWindowsSecurityEvent4663Profile.CredentialStoreRead);

    if (
        InertWindowsSecurityEvent4663Parser.RuntimeWired ||
        credential.EventFamily != "file-access" ||
        credential.ObservedAccessClass != "read" ||
        credential.RequiredObjectClass != "credential-store" ||
        secret.RequiredObjectClass != "unsecured-secret" ||
        hidden.EventFamily != "file-attribute-change" ||
        hidden.ObservedAccessClass != "write-attributes" ||
        hidden.RequiredObjectClass != "hidden-artifact" ||
        !credential.TargetSaclRequired ||
        credential.GenuineLiveEligible ||
        credential.RawEventContentRetained ||
        nativeWindows.ObservedAccessClass != "read" ||
        hidden.RequiredLocalClassifications.Contains("post-event-visibility") is false)
    {
        throw new InvalidOperationException("SENSOR_C2C_EVENT_4663_PROFILE_INVALID");
    }

    var output = JsonSerializer.Serialize(new[] { credential, secret, hidden });
    foreach (var rawValue in new[]
    {
        "inert-subject",
        "INERT-LAB",
        "S-1-5-21-2000",
        @"C:\Inert\classified-target.bin",
        @"C:\Inert\fixture-process.exe"
    })
    {
        if (output.Contains(rawValue, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("SENSOR_C2C_EVENT_4663_RAW_LEAK");
        }
    }
}

static void RejectsInertSecurity4663ParserDrift()
{
    var fixture = InertSecurity4663Fixture();
    foreach (var candidate in new[]
    {
        fixture with { ProviderName = "Microsoft-Windows-Eventlog" },
        fixture with { ChannelName = "System" },
        fixture with { EventId = 1102 },
        fixture with { Level = 4 },
        fixture with { TimeCreatedUtc = fixture.TimeCreatedUtc.ToOffset(TimeSpan.FromHours(1)) },
        fixture with { RecordId = 0 }
    })
    {
        AssertThrows<InvalidDataException>(
            () => InertWindowsSecurityEvent4663Parser.ParseCandidate(
                candidate,
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead),
            "SENSOR_C2C_EVENT_4663_METADATA_INVALID");
    }

    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurityEvent4663Parser.ParseCandidate(
            fixture with
            {
                EventData = fixture.EventData
                    .Where(pair => pair.Key != "ObjectName")
                    .ToDictionary(pair => pair.Key, pair => pair.Value)
            },
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead),
        "SENSOR_C2C_EVENT_4663_FIELDS_INVALID");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurityEvent4663Parser.ParseCandidate(
            fixture with
            {
                EventData = new Dictionary<string, string>(fixture.EventData)
                {
                    ["Message"] = "raw content"
                }
            },
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead),
        "SENSOR_C2C_EVENT_4663_FIELDS_INVALID");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurityEvent4663Parser.ParseCandidate(
            fixture with
            {
                EventData = new Dictionary<string, string>(fixture.EventData)
                {
                    ["ObjectType"] = "Key"
                }
            },
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead),
        "SENSOR_C2C_EVENT_4663_VALUES_INVALID");
    foreach (var invalidAccessList in new[]
    {
        "%%4416\n\t\t\t",
        "%%4416\r\n\t\t\t\t",
        "%%4416\n\t\t\t\t\t",
        "%%4416\nraw"
    })
    {
        AssertThrows<InvalidDataException>(
            () => InertWindowsSecurityEvent4663Parser.ParseCandidate(
                InertSecurity4663Fixture(invalidAccessList),
                InertWindowsSecurityEvent4663Profile.CredentialStoreRead),
            "SENSOR_C2C_EVENT_4663_VALUES_INVALID");
    }
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurityEvent4663Parser.ParseCandidate(
            fixture,
            InertWindowsSecurityEvent4663Profile.HiddenAttributeWrite),
        "SENSOR_C2C_EVENT_4663_ACCESS_INVALID");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurityEvent4663Parser.ParseCandidate(
            fixture,
            (InertWindowsSecurityEvent4663Profile)99),
        "SENSOR_C2C_EVENT_4663_PROFILE_INVALID");
}

static byte[] InertClassificationKey() =>
    Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();

static InertWindowsSecurity4663TargetBinding InertTargetBinding(
    InertWindowsSecurityEventRecord fixture,
    InertWindowsSecurityEvent4663Profile profile,
    byte[] key) =>
    new(
        profile,
        InertWindowsSecurity4663LocalClassifier.CreateObjectPathTagHmacSha256(
            fixture.EventData["ObjectName"], key),
        true);

static InertWindowsSecurity4663ProcessBinding InertProcessBinding(
    InertWindowsSecurityEventRecord fixture,
    byte[] key,
    InertWindowsSecurityActorTrust trust = InertWindowsSecurityActorTrust.Untrusted,
    InertWindowsSecurityTrustEvidence evidence = InertWindowsSecurityTrustEvidence.ExplicitUntrustedHash) =>
    new(
        InertWindowsSecurity4663LocalClassifier.CreateProcessPathTagHmacSha256(
            fixture.EventData["ProcessName"], key),
        InertWindowsSecuritySubjectClass.Other,
        trust,
        evidence);

static void ValidatesInertSecurity4663LocalClassifier()
{
    var key = InertClassificationKey();
    var readFixture = InertSecurity4663Fixture();
    var read = InertWindowsSecurity4663LocalClassifier.Classify(
        readFixture,
        InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
        InertTargetBinding(
            readFixture,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            key),
        InertProcessBinding(readFixture, key),
        1,
        null,
        key);
    var hiddenFixture = InertSecurity4663Fixture("%%4424", "0x100");
    var hidden = InertWindowsSecurity4663LocalClassifier.Classify(
        hiddenFixture,
        InertWindowsSecurityEvent4663Profile.HiddenAttributeWrite,
        InertTargetBinding(
            hiddenFixture,
            InertWindowsSecurityEvent4663Profile.HiddenAttributeWrite,
            key),
        InertProcessBinding(hiddenFixture, key),
        null,
        FileAttributes.Hidden | FileAttributes.Archive,
        key);

    if (
        InertWindowsSecurity4663LocalClassifier.RuntimeWired ||
        read.Mapping != new BoundedFactMapping(
            "untrusted", "read", "other", "credential-store", "success") ||
        read.BaselineState != "rare" ||
        read.VisibilityState != "unknown" ||
        !read.TargetSaclVerified ||
        !read.LocalClassificationComplete ||
        read.GenuineLiveEligible ||
        read.RawEventContentRetained ||
        hidden.Mapping.Action != "hide" ||
        hidden.VisibilityState != "hidden" ||
        !hidden.LocalClassificationComplete ||
        hidden.GenuineLiveEligible)
    {
        throw new InvalidOperationException("SENSOR_C2C_CLASSIFIER_RESULT_INVALID");
    }

    var output = JsonSerializer.Serialize(new[] { read, hidden });
    foreach (var rawValue in new[]
    {
        "inert-subject",
        "INERT-LAB",
        @"C:\Inert\classified-target.bin",
        @"C:\Inert\fixture-process.exe",
        InertWindowsSecurity4663LocalClassifier.CreateObjectPathTagHmacSha256(
            readFixture.EventData["ObjectName"], key)
    })
    {
        if (output.Contains(rawValue, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("SENSOR_C2C_CLASSIFIER_RAW_LEAK");
        }
    }
}

static void RejectsInertSecurity4663LocalClassifierDrift()
{
    var key = InertClassificationKey();
    var fixture = InertSecurity4663Fixture();
    var target = InertTargetBinding(
        fixture,
        InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
        key);
    var process = InertProcessBinding(fixture, key);

    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurity4663LocalClassifier.Classify(
            fixture,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            target with { TargetSaclConfigured = false },
            process,
            0,
            null,
            key),
        "SENSOR_C2C_CLASSIFIER_BINDING_INVALID");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurity4663LocalClassifier.Classify(
            fixture,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            target with { ObjectPathTagHmacSha256 = new string('0', 64) },
            process,
            0,
            null,
            key),
        "SENSOR_C2C_CLASSIFIER_PATH_BINDING_INVALID");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurity4663LocalClassifier.Classify(
            fixture,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            target,
            process with
            {
                ActorTrust = InertWindowsSecurityActorTrust.Managed,
                TrustEvidence = InertWindowsSecurityTrustEvidence.ExplicitUntrustedHash
            },
            0,
            null,
            key),
        "SENSOR_C2C_CLASSIFIER_TRUST_INVALID");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurity4663LocalClassifier.Classify(
            fixture,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            target,
            process,
            1_000_001,
            null,
            key),
        "SENSOR_C2C_CLASSIFIER_BASELINE_INVALID");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurity4663LocalClassifier.Classify(
            fixture,
            InertWindowsSecurityEvent4663Profile.CredentialStoreRead,
            target,
            process,
            0,
            FileAttributes.Hidden,
            key),
        "SENSOR_C2C_CLASSIFIER_VISIBILITY_UNEXPECTED");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurity4663LocalClassifier.CreateObjectPathTagHmacSha256(
            @"C:\Inert\..\escape.bin", key),
        "SENSOR_C2C_CLASSIFIER_PATH_INVALID");
    AssertThrows<InvalidDataException>(
        () => InertWindowsSecurity4663LocalClassifier.CreateObjectPathTagHmacSha256(
            @"C:\Inert\fixture.bin", key.AsSpan(0, 31)),
        "SENSOR_C2C_CLASSIFIER_KEY_INVALID");
}

static AuditHeadCheckpointRequest AuditHeadGenesisRequest() =>
    new(
        0,
        AuditHeadCheckpoint.GenesisHash,
        AuditHeadCheckpoint.GenesisHash,
        [
            new AuditHeadCheckpointLink(
                1,
                AuditHeadCheckpoint.GenesisHash,
                new string('b', 64)),
            new AuditHeadCheckpointLink(
                2,
                new string('b', 64),
                new string('c', 64))
        ]);

static void ValidatesAuditHeadCheckpoint()
{
    var wireVector = new SignedAuditHeadCheckpoint(
        AuditHeadCheckpoint.SchemaVersion,
        AuditHeadCheckpoint.Purpose,
        new string('a', 64),
        0,
        AuditHeadCheckpoint.GenesisHash,
        AuditHeadCheckpoint.GenesisHash,
        2,
        new string('c', 64),
        AuditHeadCheckpoint.SignerProfile,
        AuditHeadCheckpoint.Algorithm,
        new string('f', 64),
        string.Empty,
        string.Empty);
    var wireBytes = AuditHeadCheckpoint.CanonicalPayload(wireVector);
    try
    {
        var wireHash = Convert.ToHexString(SHA256.HashData(wireBytes))
            .ToLowerInvariant();
        if (wireHash !=
            "08c170dd7f52550d6acc9a14f8351369f642c5dfec15d8d4f4933402ce334a72")
        {
            throw new InvalidOperationException(
                "SENSOR_AUDIT_HEAD_WIRE_VECTOR_DRIFTED");
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(wireBytes);
    }

    using var signer = new FakeAuditHeadCheckpointSigner();
    var store = new FakeAuditHeadCheckpointStateStore();
    var first = AuditHeadCheckpoint.Create(
        store,
        signer,
        AuditHeadGenesisRequest());
    AuditHeadCheckpoint.Validate(first, signer.Descriptor);
    if (
        first.Sequence != 2 ||
        first.EventHash != new string('c', 64) ||
        first.PriorSequence != 0 ||
        first.PriorEventHash != AuditHeadCheckpoint.GenesisHash ||
        first.PriorCheckpointHash != AuditHeadCheckpoint.GenesisHash ||
        first.ChainId != signer.Descriptor.ChainId ||
        first.SignerPublicKeyFingerprintSha256 !=
            signer.Descriptor.PublicKeyFingerprintSha256 ||
        store.State is null ||
        store.State.Sequence != 2 ||
        store.State.CheckpointHash != first.CheckpointHash ||
        store.LastDocument?.Checkpoint != first)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_TEST_CHECKPOINT_INVALID");
    }

    var second = AuditHeadCheckpoint.Create(
        store,
        signer,
        new AuditHeadCheckpointRequest(
            first.Sequence,
            first.EventHash,
            first.CheckpointHash,
            [new AuditHeadCheckpointLink(
                3,
                first.EventHash,
                new string('d', 64))]));
    AuditHeadCheckpoint.ValidateAnchoredPrefix(
        second,
        signer.Descriptor,
        4,
        second.EventHash);
    if (
        second.Sequence != 3 ||
        second.PriorCheckpointHash != first.CheckpointHash ||
        store.State?.Sequence != 3 ||
        signer.SignCount != 2 ||
        store.CommitCount != 2)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_TEST_ADVANCE_INVALID");
    }
}

static void RejectsAuditHeadContinuityDrift()
{
    using var signer = new FakeAuditHeadCheckpointSigner();
    var store = new FakeAuditHeadCheckpointStateStore();
    var first = AuditHeadCheckpoint.Create(
        store,
        signer,
        AuditHeadGenesisRequest());

    AssertThrows<InvalidDataException>(
        () => AuditHeadCheckpoint.Create(
            store,
            signer,
            new AuditHeadCheckpointRequest(
                first.Sequence,
                first.EventHash,
                first.CheckpointHash,
                [new AuditHeadCheckpointLink(
                    4,
                    first.EventHash,
                    new string('d', 64))])),
        "SENSOR_AUDIT_HEAD_CONTINUITY_INVALID");
    AssertThrows<InvalidDataException>(
        () => AuditHeadCheckpoint.Create(
            store,
            signer,
            new AuditHeadCheckpointRequest(
                first.Sequence,
                new string('e', 64),
                first.CheckpointHash,
                [new AuditHeadCheckpointLink(
                    3,
                    new string('e', 64),
                    new string('d', 64))])),
        "SENSOR_AUDIT_HEAD_PREDECESSOR_INVALID");
    AssertThrows<InvalidDataException>(
        () => AuditHeadCheckpoint.Create(
            store,
            signer,
            new AuditHeadCheckpointRequest(
                first.Sequence,
                first.EventHash,
                first.CheckpointHash,
                [
                    new AuditHeadCheckpointLink(
                        3,
                        first.EventHash,
                        new string('d', 64)),
                    new AuditHeadCheckpointLink(
                        4,
                        new string('e', 64),
                        new string('f', 64))
                ])),
        "SENSOR_AUDIT_HEAD_CONTINUITY_INVALID");
    AssertThrows<InvalidDataException>(
        () => AuditHeadCheckpoint.ValidateAnchoredPrefix(
            first,
            signer.Descriptor,
            1,
            first.EventHash),
        "SENSOR_AUDIT_HEAD_PREFIX_INVALID");
    AssertThrows<InvalidDataException>(
        () => AuditHeadCheckpoint.ValidateAnchoredPrefix(
            first,
            signer.Descriptor,
            first.Sequence,
            new string('e', 64)),
        "SENSOR_AUDIT_HEAD_PREFIX_INVALID");
    if (store.State?.Sequence != 2 || store.CommitCount != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_TEST_DRIFT_MUTATED_STATE");
    }
}

static void RejectsAuditHeadSignerDrift()
{
    using var signer = new FakeAuditHeadCheckpointSigner();
    var store = new FakeAuditHeadCheckpointStateStore();
    var checkpoint = AuditHeadCheckpoint.Create(
        store,
        signer,
        AuditHeadGenesisRequest());

    AssertThrows<InvalidDataException>(
        () => AuditHeadCheckpoint.Validate(
            checkpoint with { EventHash = new string('e', 64) },
            signer.Descriptor),
        "SENSOR_AUDIT_HEAD_CHECKPOINT_INVALID");
    AssertThrows<InvalidDataException>(
        () => AuditHeadCheckpoint.Validate(
            checkpoint,
            signer.Descriptor with { Algorithm = "caller-selected" }),
        "SENSOR_AUDIT_HEAD_SIGNER_INVALID");
    AssertThrows<InvalidDataException>(
        () => AuditHeadCheckpoint.Validate(
            checkpoint with { SignatureBase64 = "not-base64" },
            signer.Descriptor),
        "SENSOR_AUDIT_HEAD_SIGNATURE_INVALID");

    using var corrupt = new FakeAuditHeadCheckpointSigner
    {
        CorruptSignature = true
    };
    var cleanStore = new FakeAuditHeadCheckpointStateStore();
    AssertThrows<InvalidDataException>(
        () => AuditHeadCheckpoint.Create(
            cleanStore,
            corrupt,
            AuditHeadGenesisRequest()),
        "SENSOR_AUDIT_HEAD_SIGNATURE_INVALID");
    if (cleanStore.State is not null || cleanStore.CommitCount != 0)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_TEST_CORRUPT_SIGNATURE_COMMITTED");
    }
}

static void RejectsAuditHeadCommitFailure()
{
    using var signer = new FakeAuditHeadCheckpointSigner();
    var store = new FakeAuditHeadCheckpointStateStore
    {
        RejectCommit = true
    };
    AssertThrows<InvalidOperationException>(
        () => AuditHeadCheckpoint.Create(
            store,
            signer,
            AuditHeadGenesisRequest()),
        "SENSOR_AUDIT_HEAD_STATE_CONFLICT");
    if (
        store.State is not null ||
        store.CommitCount != 1 ||
        signer.SignCount != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_TEST_FAILED_COMMIT_ADVANCED");
    }
}

static void ValidatesAuditWitnessAppendPlan()
{
    var plan = AuditWitnessAppendFilePolicy.BuildPlan();
    if (plan.RootPath !=
            @"C:\ProgramData\Project15 Audit Head\Witness" ||
        plan.FilePath !=
            @"C:\ProgramData\Project15 Audit Head\Witness\audit-witness-v1.log" ||
        plan.Claim != "historical-rewrite-detection-only" ||
        plan.MaximumBytes != 1_048_576 ||
        plan.UsersAppendFileMask != 0x0012008D ||
        !plan.SourceOnly || plan.InstallerWiringEnabled ||
        plan.RuntimeWiringEnabled || plan.CanCreate || plan.CanTruncate ||
        plan.CanDelete || plan.CanReplace)
    {
        throw new InvalidOperationException(
            "Audit-witness append plan authority drifted.");
    }
}

static void ValidatesAuditWitnessProtectedInstallerPlan()
{
    var plan = AuditWitnessProtectedFileInstaller.BuildPlan();
    if (plan.BaseRootPath !=
            @"C:\ProgramData\Project15 Audit Head" ||
        plan.RootPath !=
            @"C:\ProgramData\Project15 Audit Head\Witness" ||
        plan.FilePath !=
            @"C:\ProgramData\Project15 Audit Head\Witness\audit-witness-v1.log" ||
        plan.Claim != "historical-rewrite-detection-only" ||
        plan.MaximumBytes != 1_048_576 ||
        plan.UsersAppendFileMask != 0x0012008D ||
        !plan.RequiresAdministrator || !plan.ExistingFileNeverTruncated ||
        !plan.ExistingFileNeverReplaced ||
        !plan.FailedInstallRemovesOnlyNewEmptyObjects ||
        plan.RuntimeWiringEnabled || plan.TelemetryEnabled ||
        plan.TransportEnabled || plan.CommandChannelEnabled)
    {
        throw new InvalidOperationException(
            "Protected audit-witness installer plan drifted.");
    }
}

static void ValidatesAuditWitnessEffectiveAccessPlan()
{
    var plan = AuditWitnessProtectedFileChecker.BuildEffectiveAccessPlan();
    if (plan.FilePath !=
            @"C:\ProgramData\Project15 Audit Head\Witness\audit-witness-v1.log" ||
        plan.RequiredAppendDataAccess != 0x00000004 ||
        plan.DeniedWriteDataAccess != 0x00000002 ||
        plan.DeniedDeleteAccess != 0x00010000 ||
        plan.DeniedWriteDacAccess != 0x00040000 ||
        plan.DeniedWriteOwnerAccess != 0x00080000 ||
        !plan.RequiresStandardUser || plan.WritesBytes ||
        plan.RuntimeWiringEnabled)
    {
        throw new InvalidOperationException(
            "Audit-witness effective-access proof plan drifted.");
    }
}

static void ValidatesAuditWitnessAppendAcls()
{
    AuditWitnessAppendFilePolicy.ValidateRootSecurity(
        AuditWitnessAppendFilePolicy.CreateRootSecurity());
    AuditWitnessAppendFilePolicy.ValidateFileSecurity(
        AuditWitnessAppendFilePolicy.CreateFileSecurity());
    AuditWitnessAppendFilePolicy.ValidateFileShape(new(
        Exists: true,
        IsDirectory: false,
        IsReparsePoint: false,
        HardLinkCount: 1,
        Length: 0));
}

static void RejectsAuditWitnessAppendAclDrift()
{
    var writable = AuditWitnessAppendFilePolicy.CreateFileSecurity();
    writable.AddAccessRule(new FileSystemAccessRule(
        new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
        FileSystemRights.WriteData | FileSystemRights.Delete |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership,
        AccessControlType.Allow));
    AssertThrows<InvalidDataException>(
        () => AuditWitnessAppendFilePolicy.ValidateFileSecurity(writable));

    var unknown = AuditWitnessAppendFilePolicy.CreateFileSecurity();
    unknown.AddAccessRule(new FileSystemAccessRule(
        new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
        FileSystemRights.Read,
        AccessControlType.Allow));
    AssertThrows<InvalidDataException>(
        () => AuditWitnessAppendFilePolicy.ValidateFileSecurity(unknown));

    var wrongOwner = AuditWitnessAppendFilePolicy.CreateFileSecurity();
    wrongOwner.SetOwner(new SecurityIdentifier(
        WellKnownSidType.LocalSystemSid,
        null));
    AssertThrows<InvalidDataException>(
        () => AuditWitnessAppendFilePolicy.ValidateFileSecurity(wrongOwner));

    var inherited = AuditWitnessAppendFilePolicy.CreateRootSecurity();
    inherited.SetAccessRuleProtection(false, true);
    AssertThrows<InvalidDataException>(
        () => AuditWitnessAppendFilePolicy.ValidateRootSecurity(inherited));
}

static void RejectsAuditWitnessAppendShapeDrift()
{
    var valid = new AuditWitnessAppendFileShape(
        true, false, false, 1, 0);
    var invalid = new[]
    {
        valid with { Exists = false },
        valid with { IsDirectory = true },
        valid with { IsReparsePoint = true },
        valid with { HardLinkCount = 2 },
        valid with { Length = 1_048_577 },
        valid with { Length = -1 }
    };
    foreach (var shape in invalid)
    {
        AssertThrows<InvalidDataException>(
            () => AuditWitnessAppendFilePolicy.ValidateFileShape(shape));
    }
}

static (AuditWitnessState Genesis, AuditWitnessRecord Prepare,
    AuditWitnessState Prepared) AuditWitnessFixture()
{
    var genesis = AuditWitnessContract.CreateGenesisState(new string('a', 64));
    var prepare = AuditWitnessContract.CreatePrepare(
        genesis,
        new string('b', 64),
        "2026-08-22T12:00:01.000Z");
    var prepared = AuditWitnessContract.Advance(genesis, prepare);
    return (genesis, prepare, prepared);
}

static void MatchesAuditWitnessWireVectors()
{
    var fixture = AuditWitnessFixture();
    if (
        AuditWitnessContract.Claim !=
            "historical-rewrite-detection-only" ||
        fixture.Prepare.RecordHash !=
        "4a243de58c26c7a2b53d3af7c37cdc7a8e9881feeda151b84557c3759756792c")
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_WITNESS_PREPARE_VECTOR_DRIFTED");
    }
    var commit = AuditWitnessContract.CreateCommit(
        fixture.Prepared,
        new(1, new string('b', 64)));
    if (commit.RecordHash !=
        "13019704c881d23187c1094e7dd0bb19d73830272be573cbcbeba0a390d80ec0")
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_WITNESS_COMMIT_VECTOR_DRIFTED");
    }
}

static void ValidatesAuditWitnessPhaseOrder()
{
    var fixture = AuditWitnessFixture();
    if (
        fixture.Prepared.CommittedSequence != 0 ||
        fixture.Prepared.PendingPrepare?.RecordHash !=
            fixture.Prepare.RecordHash)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_WITNESS_PREPARE_STATE_INVALID");
    }
    AssertThrows<InvalidDataException>(
        () => AuditWitnessContract.CreateCommit(
            fixture.Prepared,
            new(0, AuditWitnessContract.GenesisHash)),
        "SENSOR_AUDIT_WITNESS_COMMIT_NOT_ALLOWED");

    var commit = AuditWitnessContract.CreateCommit(
        fixture.Prepared,
        new(1, new string('b', 64)));
    var committed = AuditWitnessContract.Advance(
        fixture.Prepared,
        commit);
    if (
        commit.PrepareRecordHash != fixture.Prepare.RecordHash ||
        committed.CommittedSequence != 1 ||
        committed.CommittedEventHash != new string('b', 64) ||
        committed.LastRecordHash != commit.RecordHash ||
        committed.PendingPrepare is not null)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_WITNESS_COMMIT_STATE_INVALID");
    }
}

static void ValidatesAuditWitnessRecovery()
{
    var fixture = AuditWitnessFixture();
    var beforeDatabase = AuditWitnessContract.Reconcile(
        fixture.Prepared,
        new(0, AuditWitnessContract.GenesisHash));
    if (
        beforeDatabase.Status != "prepare-not-database-committed" ||
        beforeDatabase.AppendCommitAllowed ||
        !beforeDatabase.OperatorReviewRequired ||
        beforeDatabase.PrepareRecordHash != fixture.Prepare.RecordHash)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_WITNESS_PREPARE_RECOVERY_INVALID");
    }

    var afterDatabase = AuditWitnessContract.Reconcile(
        fixture.Prepared,
        new(1, new string('b', 64)));
    if (
        afterDatabase.Status != "database-committed-awaiting-commit" ||
        !afterDatabase.AppendCommitAllowed ||
        afterDatabase.OperatorReviewRequired ||
        afterDatabase.PrepareRecordHash != fixture.Prepare.RecordHash)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_WITNESS_COMMIT_RECOVERY_INVALID");
    }

    var aborted = AuditWitnessContract.CreateAbort(
        fixture.Prepared,
        new(0, AuditWitnessContract.GenesisHash),
        operatorReviewConfirmed: true);
    var recovered = AuditWitnessContract.Advance(
        fixture.Prepared,
        aborted);
    var nextPrepare = AuditWitnessContract.CreatePrepare(
        recovered,
        new string('d', 64),
        "2026-08-22T12:00:02.000Z");
    if (
        aborted.Phase != AuditWitnessContract.AbortPhase ||
        recovered.CommittedSequence != 0 ||
        recovered.PendingPrepare is not null ||
        nextPrepare.Sequence != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_WITNESS_ABORT_RECOVERY_INVALID");
    }
    AssertThrows<InvalidDataException>(
        () => AuditWitnessContract.CreateAbort(
            fixture.Prepared,
            new(0, AuditWitnessContract.GenesisHash),
            operatorReviewConfirmed: false),
        "SENSOR_AUDIT_WITNESS_ABORT_OPERATOR_REVIEW_REQUIRED");

    AssertThrows<InvalidDataException>(
        () => AuditWitnessContract.Reconcile(
            fixture.Genesis,
            new(1, new string('b', 64))),
        "SENSOR_AUDIT_WITNESS_DATABASE_AHEAD_WITHOUT_PREPARE");
}

static void RejectsAuditWitnessDrift()
{
    var fixture = AuditWitnessFixture();
    var gap = fixture.Prepare with { Sequence = 2 };
    AssertThrows<InvalidDataException>(
        () => AuditWitnessContract.Advance(
            fixture.Genesis,
            gap with { RecordHash = AuditWitnessContract.RecordHash(gap) }),
        "SENSOR_AUDIT_WITNESS_SEQUENCE_INVALID");
    AssertThrows<InvalidDataException>(
        () => AuditWitnessContract.Advance(
            fixture.Prepared,
            fixture.Prepare),
        "SENSOR_AUDIT_WITNESS_RECORD_FORK_DETECTED");
    AssertThrows<InvalidDataException>(
        () => AuditWitnessContract.Reconcile(
            fixture.Prepared,
            new(1, new string('c', 64))),
        "SENSOR_AUDIT_WITNESS_DATABASE_FORK_DETECTED");

    var commit = AuditWitnessContract.CreateCommit(
        fixture.Prepared,
        new(1, new string('b', 64)));
    var bindingDrift = commit with
    {
        PrepareRecordHash = new string('c', 64)
    };
    AssertThrows<InvalidDataException>(
        () => AuditWitnessContract.Advance(
            fixture.Prepared,
            bindingDrift with
            {
                RecordHash = AuditWitnessContract.RecordHash(bindingDrift)
            }),
        "SENSOR_AUDIT_WITNESS_COMMIT_BINDING_INVALID");
    var committed = AuditWitnessContract.Advance(
        fixture.Prepared,
        commit);
    AssertThrows<InvalidDataException>(
        () => AuditWitnessContract.Reconcile(
            committed,
            new(0, AuditWitnessContract.GenesisHash)),
        "SENSOR_AUDIT_WITNESS_DATABASE_TRUNCATION_DETECTED");
}

static string AuditHeadPendingJson()
{
    const string occurredAt = "2026-08-22T12:00:01.000Z";
    const string eventType = "audit.test.1";
    const string payloadJson = "{\"sequence\":1}";
    var previousHash = AuditHeadCheckpoint.GenesisHash;
    var eventHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"{previousHash}\n{occurredAt}\n{eventType}\n{payloadJson}")))
        .ToLowerInvariant();
    return JsonSerializer.Serialize(new
    {
        schemaVersion = 1,
        priorSequence = 0,
        priorEventHash = previousHash,
        priorCheckpointHash = AuditHeadCheckpoint.GenesisHash,
        rows = new[]
        {
            new
            {
                sequence = 1,
                occurredAt,
                eventType,
                payloadJson,
                previousHash,
                eventHash
            }
        }
    });
}

static void ValidatesNativeAuditHeadWriterPlan()
{
    var plan = NativeAuditHeadWriter.BuildPlan();
    if (plan.KeyName == SensorBoundary.IdentityKeyName ||
        plan.KeyName != NativeAuditHeadWriter.KeyName ||
        plan.PendingPath != NativeAuditHeadWriter.PendingPath ||
        plan.StatePath != NativeAuditHeadWriter.StatePath ||
        !plan.Commands.SequenceEqual(
            new[] { "plan", "status", "provision" },
            StringComparer.Ordinal) ||
        plan.AcceptsCallerPath || plan.AcceptsCallerKey ||
        plan.AcceptsCallerSid || plan.AcceptsCallerService ||
        plan.AcceptsCallerAlgorithm || plan.AcceptsCallerPayload ||
        !plan.RequiresElevationForMutation ||
        plan.CheckpointEnabled ||
        !plan.StateOrdinaryUserReadable ||
        plan.StateOrdinaryUserWritable || plan.UsesSensorIdentity ||
        plan.ServiceWired || plan.IpcEnabled || plan.NetworkEnabled ||
        plan.DatabaseAccessEnabled)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_WRITER_PLAN_INVALID");
    }
    foreach (var command in plan.Commands)
    {
        _ = NativeAuditHeadWriterCommandParser.Parse([command]);
    }
    foreach (var rejected in new[]
    {
        "checkpoint", "sign", "set-key", "--path",
        SensorBoundary.IdentityKeyName
    })
    {
        AssertThrows<InvalidDataException>(
            () => NativeAuditHeadWriterCommandParser.Parse([rejected]),
            "SENSOR_AUDIT_HEAD_COMMAND_INVALID");
    }
}

static void ProvisionsNativeAuditHeadWriterKey()
{
    var store = new FakeAuditHeadWriterKeyStore();
    var result = NativeAuditHeadWriter.Provision(store);
    if (!result.AclVerified || !result.PrivateExportBlocked ||
        result.Descriptor.Profile != AuditHeadCheckpoint.SignerProfile ||
        result.Descriptor.ChainId == AuditHeadCheckpoint.GenesisHash ||
        store.CreateCount != 1 || store.Identity.DeleteCount != 0 ||
        Convert.FromBase64String(result.ProofSignatureBase64).Length != 64)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_KEY_PROVISION_TEST_INVALID");
    }
    AssertThrows<CryptographicException>(
        () => NativeAuditHeadWriter.Provision(store),
        "SENSOR_AUDIT_HEAD_KEY_ALREADY_EXISTS");
}

static void RejectsNativeAuditHeadWriterKeyDrift()
{
    var metadataStore = new FakeAuditHeadWriterKeyStore();
    metadataStore.Identity.MetadataValue =
        metadataStore.Identity.MetadataValue with
        {
            KeyName = SensorBoundary.IdentityKeyName
        };
    AssertThrows<CryptographicException>(
        () => NativeAuditHeadWriter.Provision(metadataStore),
        "SENSOR_AUDIT_HEAD_KEY_POLICY_INVALID");
    if (metadataStore.Identity.DeleteCount != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_BAD_KEY_NOT_REMOVED");
    }

    var aclStore = new FakeAuditHeadWriterKeyStore();
    aclStore.Identity.SecurityDescriptor =
        NativeKeyAccessPolicy.CreateProtectedDescriptor();
    AssertThrows<CryptographicException>(
        () => NativeAuditHeadWriter.Provision(aclStore),
        "SENSOR_AUDIT_HEAD_KEY_ACL_INVALID");
    if (aclStore.Identity.DeleteCount != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_BAD_ACL_KEY_NOT_REMOVED");
    }

    var exportStore = new FakeAuditHeadWriterKeyStore();
    exportStore.Identity.PrivateExportBlocked = false;
    AssertThrows<CryptographicException>(
        () => NativeAuditHeadWriter.Provision(exportStore),
        "SENSOR_AUDIT_HEAD_KEY_EXPORTABLE");
    if (exportStore.Identity.DeleteCount != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_EXPORTABLE_KEY_NOT_REMOVED");
    }
}

static void ValidatesNativeAuditHeadWriterCheckpoint()
{
    var keyStore = new FakeAuditHeadWriterKeyStore { Provisioned = true };
    var stateStore = new FakeAuditHeadCheckpointStateStore();
    var pending = new FakeAuditHeadPendingProofStore(AuditHeadPendingJson());
    var checkpoint = NativeAuditHeadWriter.Checkpoint(
        keyStore,
        pending,
        stateStore);
    AuditHeadCheckpoint.Validate(
        checkpoint,
        keyStore.Identity.Descriptor);
    if (checkpoint.Sequence != 1 || stateStore.State?.Sequence != 1 ||
        pending.ReadCount != 1 || keyStore.OpenCount != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_NATIVE_CHECKPOINT_INVALID");
    }
}

static void RejectsNativeAuditHeadPendingDrift()
{
    AssertThrows<InvalidDataException>(
        () => NativeAuditHeadWriter.ParsePending(
            AuditHeadPendingJson().Replace(
                "\"rows\"",
                "\"path\":\"C:\\\\temp\",\"rows\"",
                StringComparison.Ordinal)),
        "SENSOR_AUDIT_HEAD_PENDING_INVALID");
    AssertThrows<InvalidDataException>(
        () => NativeAuditHeadWriter.ParsePending("{\"schemaVersion\":1}"),
        "SENSOR_AUDIT_HEAD_PENDING_INVALID");
    AssertThrows<InvalidDataException>(
        () => NativeAuditHeadWriter.ParsePending(
            AuditHeadPendingJson().Replace(
                "{\\u0022sequence\\u0022:1}",
                "{\\u0022sequence\\u0022:2}",
                StringComparison.Ordinal)),
        "SENSOR_AUDIT_HEAD_PENDING_HASH_INVALID");

    var keyStore = new FakeAuditHeadWriterKeyStore { Provisioned = true };
    var stateStore = new FakeAuditHeadCheckpointStateStore();
    var pending = new FakeAuditHeadPendingProofStore(AuditHeadPendingJson());
    _ = NativeAuditHeadWriter.Checkpoint(keyStore, pending, stateStore);
    AssertThrows<InvalidDataException>(
        () => NativeAuditHeadWriter.Checkpoint(
            keyStore,
            pending,
            stateStore),
        "SENSOR_AUDIT_HEAD_PREDECESSOR_INVALID");
    if (stateStore.State?.Sequence != 1 || stateStore.CommitCount != 1)
    {
        throw new InvalidOperationException(
            "SENSOR_AUDIT_HEAD_REPLAY_MUTATED_STATE");
    }
}

static void RejectsNativeAuditHeadFileDrift()
{
    AuditHeadWriterFilePolicy.ValidatePendingShape(
        new(true, false, false, 1, 100));
    AuditHeadWriterFilePolicy.ValidateStateShape(
        new(true, false, false, 1, 100));
    AssertThrows<InvalidDataException>(
        () => AuditHeadWriterFilePolicy.ValidatePendingShape(
            new(true, false, true, 1, 100)),
        "SENSOR_AUDIT_HEAD_PENDING_FILE_INVALID");
    AssertThrows<InvalidDataException>(
        () => AuditHeadWriterFilePolicy.ValidatePendingShape(
            new(true, false, false, 2, 100)),
        "SENSOR_AUDIT_HEAD_PENDING_FILE_INVALID");
    AssertThrows<InvalidDataException>(
        () => AuditHeadWriterFilePolicy.ValidateStateShape(
            new(true, false, false, 1,
                AuditHeadWriterFilePolicy.MaximumStateBytes + 1)),
        "SENSOR_AUDIT_HEAD_STATE_FILE_INVALID");

    var safe = AuditHeadWriterFilePolicy.CreateStateSecurity();
    AuditHeadWriterFilePolicy.ValidateStateSecurity(safe);
    NativeAuditHeadWriterStorage.ValidateDirectorySecurity(
        NativeAuditHeadWriterStorage.CreateDirectorySecurity(
            usersMayWrite: false),
        usersMayWrite: false);
    NativeAuditHeadWriterStorage.ValidateDirectorySecurity(
        NativeAuditHeadWriterStorage.CreateDirectorySecurity(
            usersMayWrite: true),
        usersMayWrite: true);
    safe.AddAccessRule(new FileSystemAccessRule(
        new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
        FileSystemRights.Write,
        AccessControlType.Allow));
    AssertThrows<InvalidDataException>(
        () => AuditHeadWriterFilePolicy.ValidateStateSecurity(safe),
        "SENSOR_AUDIT_HEAD_STATE_ACL_INVALID");
}

static void AssertThrows<TException>(
    Action action,
    string? expectedMessage = null)
    where TException : Exception
{
    try
    {
        action();
    }
    catch (TException exception)
    {
        if (
            expectedMessage is not null &&
            exception.Message != expectedMessage)
        {
            throw new InvalidOperationException(
                "SENSOR_TEST_EXCEPTION_MESSAGE_INVALID");
        }
        return;
    }
    throw new InvalidOperationException("SENSOR_TEST_EXCEPTION_NOT_THROWN");
}

internal sealed class FakeAuditHeadWriterKeyStore :
    IAuditHeadWriterKeyStore
{
    public FakeAuditHeadWriterIdentity Identity { get; } = new();
    public bool Provisioned { get; set; }
    public int CreateCount { get; private set; }
    public int OpenCount { get; private set; }

    public bool Exists() => Provisioned || CreateCount > 0;

    public IAuditHeadWriterIdentity Open()
    {
        OpenCount++;
        return Identity;
    }

    public IAuditHeadWriterIdentity Create()
    {
        CreateCount++;
        return Identity;
    }
}

internal sealed class FakeAuditHeadWriterIdentity :
    IAuditHeadWriterIdentity
{
    private readonly ECDsa signer =
        ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public FakeAuditHeadWriterIdentity()
    {
        var spki = signer.ExportSubjectPublicKeyInfo();
        var fingerprint = Convert.ToHexString(SHA256.HashData(spki))
            .ToLowerInvariant();
        Descriptor = new(
            AuditHeadCheckpoint.SignerProfile,
            AuditHeadCheckpoint.DeriveChainId(fingerprint),
            AuditHeadCheckpoint.Algorithm,
            AuditHeadCheckpoint.PublicKeyFormat,
            Convert.ToBase64String(spki),
            fingerprint,
            AuditHeadCheckpoint.KeyPersistence);
        CryptographicOperations.ZeroMemory(spki);
    }

    public NativeKeyMetadata MetadataValue { get; set; } = new(
        NativeAuditHeadWriter.KeyName,
        SensorBoundary.SoftwareProviderName,
        CngAlgorithm.ECDsaP256.Algorithm,
        CngAlgorithmGroup.ECDsa.AlgorithmGroup,
        256,
        true,
        false,
        CngExportPolicies.None,
        CngKeyUsages.Signing);
    public byte[] SecurityDescriptor { get; set; } =
        AuditHeadWriterKeyPolicy.CreateDescriptor();
    public bool PrivateExportBlocked { get; set; } = true;
    public int DeleteCount { get; private set; }
    public NativeKeyMetadata Metadata => MetadataValue;
    public AuditHeadSignerDescriptor Descriptor { get; }

    public byte[] ReadSecurityDescriptor() => [.. SecurityDescriptor];

    public bool IsPrivateExportBlocked() => PrivateExportBlocked;

    public byte[] Sign(ReadOnlySpan<byte> payload) => signer.SignData(
        payload,
        HashAlgorithmName.SHA256,
        DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public void Delete()
    {
        DeleteCount++;
    }

    public void Dispose()
    {
        // Retained for assertions across pure workflow calls.
    }
}

internal sealed class FakeAuditHeadPendingProofStore(string json) :
    IAuditHeadPendingProofStore
{
    public int ReadCount { get; private set; }

    public string ReadFixed()
    {
        ReadCount++;
        return json;
    }
}

internal sealed class FakeAuditHeadCheckpointSigner :
    IAuditHeadCheckpointSigner,
    IDisposable
{
    private readonly ECDsa signer =
        ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public FakeAuditHeadCheckpointSigner()
    {
        var spki = signer.ExportSubjectPublicKeyInfo();
        var fingerprint = Convert.ToHexString(SHA256.HashData(spki))
            .ToLowerInvariant();
        Descriptor = new AuditHeadSignerDescriptor(
            AuditHeadCheckpoint.SignerProfile,
            AuditHeadCheckpoint.DeriveChainId(fingerprint),
            AuditHeadCheckpoint.Algorithm,
            AuditHeadCheckpoint.PublicKeyFormat,
            Convert.ToBase64String(spki),
            fingerprint,
            AuditHeadCheckpoint.KeyPersistence);
        CryptographicOperations.ZeroMemory(spki);
    }

    public AuditHeadSignerDescriptor Descriptor { get; }
    public bool CorruptSignature { get; set; }
    public int SignCount { get; private set; }

    public byte[] Sign(ReadOnlySpan<byte> payload)
    {
        SignCount++;
        var signature = signer.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (CorruptSignature)
        {
            signature[0] ^= 0xff;
        }
        return signature;
    }

    public void Dispose()
    {
        signer.Dispose();
    }
}

internal sealed class FakeAuditHeadCheckpointStateStore :
    IAuditHeadCheckpointStateStore
{
    public AuditHeadProtectedState? State { get; private set; }
    public AuditHeadProtectedDocument? LastDocument { get; private set; }
    public bool RejectCommit { get; set; }
    public int CommitCount { get; private set; }

    public AuditHeadProtectedState? Read() => State;

    public bool TryCommit(
        AuditHeadProtectedState? expected,
        AuditHeadProtectedDocument next)
    {
        CommitCount++;
        if (RejectCommit || State != expected)
        {
            return false;
        }
        State = AuditHeadCheckpoint.ValidateProtectedDocument(next);
        LastDocument = next;
        return true;
    }
}

internal sealed record NativeTelemetryWireVector(
    string CoreJson,
    string CertificateFingerprintSha256,
    string CanonicalPayload,
    string BatchHash,
    string PublicKeySpkiBase64,
    string SignatureBase64);

internal sealed class FakeWindowsEventLogMetadataReader(
    Func<WindowsEventLogSource, WindowsEventLogMetadata> read) :
    IWindowsEventLogMetadataReader
{
    public List<WindowsEventLogSource> Requested { get; } = [];

    public WindowsEventLogMetadata Read(WindowsEventLogSource source)
    {
        Requested.Add(source);
        return read(source);
    }
}

internal sealed class FakeBoundedEventMetadataReader(
    Func<BoundedEventFamily, BoundedEventReadResult> read) :
    IBoundedEventMetadataReader
{
    public List<BoundedEventFamily> Requested { get; } = [];

    public BoundedEventReadResult ReadOne(
        BoundedEventFamily family,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Requested.Add(family);
        return read(family);
    }
}

internal sealed class FakeGenuineScmEventReader(
    GenuineScmEventMetadata? metadata) : IGenuineScmEventReader
{
    public int ReadCount { get; private set; }

    public GenuineScmEventMetadata? ReadOne(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ReadCount++;
        if (ReadCount > NativeGenuineScmEventReader.MaximumRecords)
        {
            throw new InvalidOperationException("genuine event reader exceeded one record");
        }
        return metadata;
    }
}

internal sealed class FakeSensorServiceIdentity(string? currentSid) :
    ISensorServiceIdentity
{
    public string? CurrentSid { get; } = currentSid;
}

internal sealed class FakeSensorStartupModeSource(string? value) :
    ISensorStartupModeSource
{
    public string? ReadExactMode() => value;
}

internal sealed class FakeEndpointBindingStore : IEndpointBindingStore
{
    public string? Binding { get; init; }
    public string? CapabilityProof { get; set; }
    public int WriteCount { get; private set; }
    public string? ReadBinding() => Binding;
    public string? ReadCapabilityProof() => CapabilityProof;
    public void WriteCapabilityProof(string json)
    {
        WriteCount++;
        CapabilityProof = json;
    }
}

internal sealed class FakeGenuineProofStore(string? proof) : IGenuineScmProofStore
{
    public string? ReadExisting() => proof;
    public byte[] ReadSourceSalt() => throw new InvalidOperationException("not used");
    public void Write(string json) => throw new InvalidOperationException("not used");
}

internal sealed class FakeBoundedCollectorProofStore(byte[] salt) :
    IBoundedCollectorProofStore
{
    public string? Document { get; private set; }
    public int WriteCount { get; private set; }
    public string? ReadExisting() => Document;
    public byte[] ReadSourceSalt() => [.. salt];
    public void Write(string json)
    {
        WriteCount++;
        Document = json;
    }
}

internal sealed class FakeEndpointDeliveryStore : IEndpointDeliveryStore
{
    public string? Document { get; set; }
    public int WriteCount { get; private set; }
    public string? ReadExisting() => Document;
    public void Write(string json)
    {
        WriteCount++;
        Document = json;
    }
}

internal sealed class FakeManifestTimestampReader(DateTime value) :
    IInstallManifestTimestampReader
{
    public DateTime ReadUtc() => value;
}

internal sealed class FakeEndpointDeliveryTransport : ILoopbackFactTransport
{
    public int SendCount { get; private set; }
    public Exception? Failure { get; init; }

    public Task<LoopbackFactReceipt> SendOnceAsync(
        LocalSyntheticSignedBatch batch,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SendCount++;
        if (Failure is not null) return Task.FromException<LoopbackFactReceipt>(Failure);
        return Task.FromResult(new LoopbackFactReceipt(
            1, "accepted", batch.BatchHash, batch.BatchSequence, 1));
    }
}

internal sealed class FakeInstallManifestBindingReader(InstallManifestBinding value) :
    IInstallManifestBindingReader
{
    public int ReadCount { get; private set; }

    public InstallManifestBinding Read()
    {
        ReadCount++;
        return value;
    }
}

internal sealed class FixedTestTimeProvider(DateTime utcNow) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => new(utcNow);
}

internal sealed class FakeKeyStore : INativeIdentityKeyStore
{
    public bool KeyExists { get; init; }
    public int OpenCount { get; private set; }
    public int CreateCount { get; private set; }
    public FakeProvisionedIdentity Identity { get; } = new();

    public bool Exists() => KeyExists;

    public IProvisionedNativeIdentity Open()
    {
        OpenCount++;
        return Identity;
    }

    public IProvisionedNativeIdentity Create()
    {
        CreateCount++;
        return Identity;
    }
}

internal sealed class FakeProvisionedIdentity : IProvisionedNativeIdentity
{
    private readonly ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public NativeKeyMetadata Metadata { get; set; } = ValidMetadata();
    public byte[] SecurityDescriptor { get; set; } =
        NativeKeyAccessPolicy.CreateProtectedDescriptor();
    public bool PrivateExportBlocked { get; set; } = true;
    public bool CorruptSignature { get; set; }
    public int DeleteCount { get; private set; }

    public byte[] ReadSecurityDescriptor() => [.. SecurityDescriptor];

    public byte[] ExportPublicKeySpki() => signer.ExportSubjectPublicKeyInfo();

    public byte[] Sign(ReadOnlySpan<byte> payload)
    {
        var signature = NativeSignatureProfile.Sign(signer, payload);
        if (CorruptSignature)
        {
            signature[0] ^= 0xff;
        }
        return signature;
    }

    public bool IsPrivateExportBlocked() => PrivateExportBlocked;

    public void Delete()
    {
        DeleteCount++;
    }

    public void Dispose()
    {
        // The fake deliberately remains inspectable after workflow disposal.
    }

    private static NativeKeyMetadata ValidMetadata() =>
        new(
            SensorBoundary.IdentityKeyName,
            SensorBoundary.SoftwareProviderName,
            CngAlgorithm.ECDsaP256.Algorithm,
            CngAlgorithmGroup.ECDsa.AlgorithmGroup,
            256,
            IsMachineKey: true,
            IsEphemeral: false,
            CngExportPolicies.None,
            CngKeyUsages.Signing);
}

internal sealed class FakeSensorIdentitySigner : ISensorIdentitySigner
{
    private readonly ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public bool CorruptSignature { get; set; }

    public SensorIdentityDescriptor Descriptor
    {
        get
        {
            var spki = signer.ExportSubjectPublicKeyInfo();
            return new SensorIdentityDescriptor(
                SensorBoundary.SignatureAlgorithm,
                "spki-der",
                Convert.ToBase64String(spki),
                Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant(),
                SensorBoundary.SoftwareProviderName,
                "non-exportable-machine-cng-software-ksp");
        }
    }

    public string SignUtf8Payload(string payload)
    {
        var signature = NativeSignatureProfile.Sign(signer, Encoding.UTF8.GetBytes(payload));
        if (CorruptSignature)
        {
            signature[0] ^= 0xff;
        }
        return Convert.ToBase64String(signature);
    }

    public void Dispose()
    {
        signer.Dispose();
    }
}

internal sealed class FakeLoopbackHandler(
    Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) :
    HttpMessageHandler
{
    public int SendCount { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        SendCount++;
        return send(request, cancellationToken);
    }
}

internal sealed class FakeDiagnosticProbeStore : IDiagnosticProbeKeyStore
{
    public bool KeyExists { get; set; }
    public int OpenCount { get; private set; }
    public FakeDiagnosticProbeKey Key { get; }

    public FakeDiagnosticProbeStore()
    {
        Key = new FakeDiagnosticProbeKey(this);
    }

    public bool Exists() => KeyExists;

    public IDiagnosticProbeKey Open()
    {
        OpenCount++;
        return Key;
    }
}

internal sealed class FakeDiagnosticProbeKey(
    FakeDiagnosticProbeStore store) : IDiagnosticProbeKey
{
    public NativeKeyMetadata Metadata { get; set; } =
        new(
            DiagnosticProbeCleanup.ProbeName,
            SensorBoundary.SoftwareProviderName,
            CngAlgorithm.ECDsaP256.Algorithm,
            CngAlgorithmGroup.ECDsa.AlgorithmGroup,
            256,
            IsMachineKey: false,
            IsEphemeral: false,
            CngExportPolicies.None,
            CngKeyUsages.Signing);

    public int DeleteCount { get; private set; }

    public void Delete()
    {
        DeleteCount++;
        store.KeyExists = false;
    }

    public void Dispose()
    {
        // The fake deliberately remains inspectable after workflow disposal.
    }
}

internal sealed record FakeSecurity4663ReadinessProbe(
    Security4663ChannelObservation Channel,
    Security4663AuditPolicyObservation AuditPolicy,
    Func<Security4663TargetReadinessDefinition,
        Security4663TargetObservation> TargetFactory) :
    ISecurity4663ReadinessProbe
{
    public int ChannelCalls { get; private set; }
    public int AuditPolicyCalls { get; private set; }
    public int TargetCalls { get; private set; }

    public static FakeSecurity4663ReadinessProbe Ready() =>
        new(
            new(true, true, null),
            new(true, true, false, null),
            target => new(
                target.ProfileId,
                true,
                true,
                false,
                true,
                true,
                null));

    public Security4663ChannelObservation InspectChannel()
    {
        ChannelCalls++;
        return Channel;
    }

    public Security4663AuditPolicyObservation InspectAuditPolicy()
    {
        AuditPolicyCalls++;
        return AuditPolicy;
    }

    public Security4663TargetObservation InspectTarget(
        Security4663TargetReadinessDefinition target)
    {
        TargetCalls++;
        return TargetFactory(target);
    }
}

internal sealed class FakeSecurity4663OneShotReader(
    Security4663OneShotReadResult result) : ISecurity4663OneShotReader
{
    public int Calls { get; private set; }
    public Security4663OneShotReadRequest? LastRequest { get; private set; }

    public Security4663OneShotReadResult ReadOne(
        Security4663OneShotReadRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        LastRequest = request;
        return result;
    }
}

internal sealed class FakeSecurity4663OneShotEventSource(
    Security4663OneShotSourceResult result) : ISecurity4663OneShotEventSource
{
    public int Calls { get; private set; }
    public Security4663OneShotSourceQuery? LastQuery { get; private set; }

    public Security4663OneShotSourceResult ReadOne(
        Security4663OneShotSourceQuery query,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        LastQuery = query;
        return result;
    }
}

internal sealed class FakeSecurity4663EventLogSession(
    string? eventXml) : ISecurity4663EventLogSession
{
    public int ReadCalls { get; private set; }
    public TimeSpan? LastTimeout { get; private set; }
    public bool Disposed { get; private set; }

    public string? ReadOneXml(TimeSpan timeout)
    {
        ReadCalls++;
        LastTimeout = timeout;
        return eventXml;
    }

    public void Dispose() => Disposed = true;
}

internal sealed class FakeSecurity4663EventLogSessionFactory :
    ISecurity4663EventLogSessionFactory
{
    private readonly ISecurity4663EventLogSession? _session;
    private readonly Exception? _error;

    public FakeSecurity4663EventLogSessionFactory(
        ISecurity4663EventLogSession session)
    {
        _session = session;
    }

    public FakeSecurity4663EventLogSessionFactory(Exception error)
    {
        _error = error;
    }

    public int Calls { get; private set; }
    public Security4663OneShotSourceQuery? LastQuery { get; private set; }

    public ISecurity4663EventLogSession Open(
        Security4663OneShotSourceQuery query)
    {
        Calls++;
        LastQuery = query;
        if (_error is not null) throw _error;
        return _session ?? throw new InvalidOperationException(
            "fake session missing");
    }
}

internal sealed class FakeSecurity4663LogMetadataSource(
    Security4663LogMetadata metadata) : ISecurity4663LogMetadataSource
{
    public int Calls { get; private set; }

    public Security4663LogMetadata ReadSecurityLogMetadata()
    {
        Calls++;
        return metadata;
    }
}

internal sealed class FakeSecurity4663LogInformationSession(
    Security4663LogMetadata metadata) : ISecurity4663LogInformationSession
{
    public int Calls { get; private set; }
    public string? LastLogName { get; private set; }
    public System.Diagnostics.Eventing.Reader.PathType? LastPathType {
        get;
        private set;
    }

    public Security4663LogMetadata Read(
        string logName,
        System.Diagnostics.Eventing.Reader.PathType pathType)
    {
        Calls++;
        LastLogName = logName;
        LastPathType = pathType;
        return metadata;
    }
}

internal sealed class FakeSecurity4663OneShotApprovalStore :
    ISecurity4663OneShotApprovalStore,
    ISecurity4663OneShotApprovalAbsenceVerifier
{
    public string? Document { get; set; }
    public int WriteCount { get; private set; }
    public int ConsumeCount { get; private set; }
    public int ReadCount { get; private set; }
    public int AbsentCheckCount { get; private set; }

    public string? ReadExisting()
    {
        ReadCount++;
        return Document;
    }

    public void WriteNew(string json)
    {
        if (Document is not null)
        {
            throw new InvalidOperationException("fake approval overwrite");
        }
        WriteCount++;
        Document = json;
    }

    public void ConsumeExact(string expectedJson)
    {
        if (!string.Equals(Document, expectedJson, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "fake approval consume mismatch");
        }
        ConsumeCount++;
        Document = null;
    }

    public bool VerifyAbsent()
    {
        AbsentCheckCount++;
        return Document is null;
    }
}

internal sealed class FakeSecurity4663LiveOneShotApprovalStore :
    ISecurity4663LiveOneShotApprovalOperatorStore
{
    public string? Document { get; set; }
    public int WriteCount { get; private set; }
    public int ConsumeCount { get; private set; }
    public int ReadCount { get; private set; }
    public int CleanupCount { get; private set; }
    public int AbsentCheckCount { get; private set; }

    public string? ReadExisting()
    {
        ReadCount++;
        return Document;
    }

    public void WriteNew(string json)
    {
        if (Document is not null)
        {
            throw new InvalidOperationException("fake live approval overwrite");
        }
        WriteCount++;
        Document = json;
    }

    public void ConsumeExact(string expectedJson)
    {
        if (!string.Equals(Document, expectedJson, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "fake live approval consume mismatch");
        }
        ConsumeCount++;
        Document = null;
    }

    public bool RemoveForRecovery()
    {
        if (Document is null)
        {
            return false;
        }
        CleanupCount++;
        Document = null;
        return true;
    }

    public bool VerifyAbsent()
    {
        AbsentCheckCount++;
        return Document is null;
    }
}

internal sealed class FakeSecurity4663LiveOneShotResultStore :
    ISecurity4663LiveOneShotResultStore
{
    public string? Document { get; set; }
    public int ReadCount { get; private set; }
    public int WriteCount { get; private set; }

    public string? ReadExisting()
    {
        ReadCount++;
        return Document;
    }

    public void WriteNew(string json)
    {
        if (Document is not null)
        {
            throw new InvalidOperationException("fake live result overwrite");
        }
        WriteCount++;
        Document = json;
    }
}

internal sealed class FakeSecurity4663LiveOneShotResultOperatorStore :
    ISecurity4663LiveOneShotResultOperatorStore
{
    public string? Document { get; set; }
    public bool Prepared { get; set; }
    public int PrepareCount { get; private set; }
    public int ConsumeCount { get; private set; }
    public int CleanupCount { get; private set; }

    public void PrepareEmpty()
    {
        if (Document is not null || Prepared)
        {
            throw new InvalidOperationException("fake live result slot exists");
        }
        Prepared = true;
        PrepareCount++;
        Document = string.Empty;
    }

    public bool VerifyEmpty() => Prepared && Document == string.Empty;

    public string? ReadExisting() =>
        Prepared && !string.IsNullOrEmpty(Document) ? Document : null;

    public void ConsumeExact(string expectedJson)
    {
        if (!string.Equals(Document, expectedJson, StringComparison.Ordinal))
        {
            throw new InvalidDataException("fake live result consume mismatch");
        }
        ConsumeCount++;
        Prepared = false;
        Document = null;
    }

    public bool VerifyAbsent() => !Prepared && Document is null;

    public bool CleanupBoundedProtected()
    {
        if (!Prepared && Document is null)
        {
            return false;
        }
        if (!Prepared)
        {
            throw new InvalidDataException("fake unprotected live result");
        }
        CleanupCount++;
        Prepared = false;
        Document = null;
        return true;
    }
}

internal sealed class FakeSecurity4663OneShotResultStore :
    ISecurity4663OneShotResultStore
{
    public string? Document { get; set; }
    public int WriteCount { get; private set; }
    public int ConsumeCount { get; private set; }

    public string? ReadExisting() => Document;

    public void WriteNew(string json)
    {
        if (Document is not null)
        {
            throw new InvalidOperationException("fake result overwrite");
        }
        WriteCount++;
        Document = json;
    }

    public void ConsumeExact(string expectedJson)
    {
        if (!string.Equals(Document, expectedJson, StringComparison.Ordinal))
        {
            throw new InvalidDataException("fake result consume mismatch");
        }
        ConsumeCount++;
        Document = null;
    }
}

internal sealed class FakeSecurity4663OneShotResultOperatorStore :
    ISecurity4663OneShotResultOperatorStore
{
    public string? Document { get; set; }
    public bool Prepared { get; set; }
    public int PrepareCount { get; private set; }
    public int ConsumeCount { get; private set; }
    public int CleanupCount { get; private set; }

    public void PrepareEmpty()
    {
        if (Document is not null || Prepared)
        {
            throw new InvalidOperationException("fake result slot exists");
        }
        Prepared = true;
        PrepareCount++;
        Document = string.Empty;
    }

    public bool VerifyEmpty() => Prepared && Document == string.Empty;

    public string? ReadExisting() =>
        Prepared && !string.IsNullOrEmpty(Document) ? Document : null;

    public void ConsumeExact(string expectedJson)
    {
        if (!string.Equals(Document, expectedJson, StringComparison.Ordinal))
        {
            throw new InvalidDataException("fake result consume mismatch");
        }
        ConsumeCount++;
        Prepared = false;
        Document = null;
    }

    public bool VerifyAbsent() => !Prepared && Document is null;

    public bool CleanupBoundedProtected()
    {
        if (!Prepared && Document is null)
        {
            return false;
        }
        if (!Prepared)
        {
            throw new InvalidDataException("fake unprotected result");
        }
        CleanupCount++;
        Prepared = false;
        Document = null;
        return true;
    }
}

internal sealed class FakeSecurity4663CeremonyStore(
    string? failAt = null) : ISecurity4663CeremonyStore
{
    private readonly Security4663CeremonySnapshot snapshot =
        Security4663ReadinessCeremony.CreateSnapshot(
            "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)",
            3);

    public List<string> Calls { get; } = [];

    public void RequireAdministrator() => Record("admin");
    public void ValidateServiceIdentity() => Record("identity");
    public void ValidateApplyPreconditions() => Record("preconditions");

    public Security4663CeremonySnapshot CaptureOriginalState()
    {
        Record("capture");
        return snapshot;
    }

    public void WriteProtectedState(Security4663CeremonySnapshot value)
    {
        Security4663ReadinessCeremony.ValidateSnapshot(value);
        Record("write-state");
    }

    public void ApplyChannelReadOnlyAce() => Record("channel");
    public void ApplyAuditSuccessOnly() => Record("audit");
    public void CreateFixedTargets() => Record("targets");

    public Security4663ReadinessCheckResult CheckReadiness()
    {
        Record("check");
        return Security4663ReadinessCheck.Check(
            FakeSecurity4663ReadinessProbe.Ready());
    }

    public void RecoverFailedApply(Security4663CeremonySnapshot value)
    {
        Security4663ReadinessCeremony.ValidateSnapshot(value);
        Record("recover");
    }

    public Security4663CeremonySnapshot ReadProtectedState()
    {
        Record("read-state");
        return snapshot;
    }

    public void ValidateRollbackPreconditions(
        Security4663CeremonySnapshot value)
    {
        Security4663ReadinessCeremony.ValidateSnapshot(value);
        Record("rollback-preconditions");
    }

    public void RestoreOriginalState(Security4663CeremonySnapshot value)
    {
        Security4663ReadinessCeremony.ValidateSnapshot(value);
        Record("restore");
    }

    public void RemoveFixedTargetsAndState() => Record("remove");

    private void Record(string operation)
    {
        Calls.Add(operation);
        if (string.Equals(operation, failAt, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"test-failure-{operation}");
        }
    }
}

internal sealed class FakeServiceSidAuthority(ServiceSidNativeSnapshot snapshot)
    : IServiceSidNativeAuthority
{
    public ServiceSidNativeSnapshot ReadFixedService() => snapshot;
}

internal sealed record FakeServiceSidConfigurationNative :
    IServiceSidConfigurationNative
{
    public string ServiceName { get; init; } = SensorBoundary.ServiceName;
    public string ScmLogonAccount { get; init; } =
        SensorBoundary.ExpectedServiceIdentity;
    public string AccountName { get; init; } =
        ServiceSidAuthority.AccountName;
    public string DomainName { get; init; } =
        ServiceSidAuthority.DomainName;
    public string Sid { get; init; } = "S-1-5-80-1-2-3-4-5";
    public uint CurrentSidType { get; private set; }
    public int ReadCalls { get; private set; }
    public int SetCalls { get; private set; }
    public int? IgnoreSetNumber { get; set; }

    public static FakeServiceSidConfigurationNative Create(uint sidType) =>
        new() { CurrentSidType = sidType };

    public ServiceSidNativeSnapshot ReadFixedService()
    {
        ReadCalls++;
        return new(
            ServiceName,
            ScmLogonAccount,
            AccountName,
            DomainName,
            Sid,
            CurrentSidType);
    }

    public void SetFixedServiceSidType(uint serviceSidType)
    {
        SetCalls++;
        if (IgnoreSetNumber != SetCalls)
        {
            CurrentSidType = serviceSidType;
        }
    }
}
