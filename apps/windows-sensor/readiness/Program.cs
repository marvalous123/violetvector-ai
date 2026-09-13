using System.Text.Json;
using WARRoom.WindowsSensor.Readiness;

try
{
    var command = WindowsEventSourceReadinessCommandParser.Parse(args);
    var jsonOptions = new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };
    if (command == WindowsEventSourceReadinessCommand.Plan)
    {
        Console.WriteLine(
            JsonSerializer.Serialize(
                new
                {
                    ok = true,
                    command = "source-readiness-plan",
                    result = WindowsEventSourceReadiness.BuildPlan()
                },
                jsonOptions));
        return 0;
    }

    if (command == WindowsEventSourceReadinessCommand.Security4663Plan)
    {
        var plan = Security4663MachineReadiness.BuildPlan();
        Security4663MachineReadiness.ValidatePlan(plan);
        Console.WriteLine(
            JsonSerializer.Serialize(
                new
                {
                    ok = true,
                    command = "security-4663-readiness-plan",
                    result = plan
                },
                jsonOptions));
        return 0;
    }

    if (command == WindowsEventSourceReadinessCommand.Security4663Check)
    {
        var securityResult = Security4663ReadinessCheck.Check(
            new NativeSecurity4663ReadinessProbe());
        Console.WriteLine(
            JsonSerializer.Serialize(
                new
                {
                    ok = true,
                    command = "security-4663-readiness-check",
                    result = securityResult
                },
                jsonOptions));
        return securityResult.Ready ? 0 : 2;
    }

    if (command == WindowsEventSourceReadinessCommand.Security4663CeremonyPlan)
    {
        var ceremonyPlan = Security4663ReadinessCeremony.BuildPlan();
        Security4663ReadinessCeremony.ValidatePlan(ceremonyPlan);
        Console.WriteLine(
            JsonSerializer.Serialize(
                new
                {
                    ok = true,
                    command = "security-4663-ceremony-plan",
                    result = ceremonyPlan
                },
                jsonOptions));
        return 0;
    }

    if (command == WindowsEventSourceReadinessCommand.Security4663Apply)
    {
        var ceremonyResult = Security4663ReadinessCeremony.Apply(
            new NativeSecurity4663CeremonyStore());
        Console.WriteLine(
            JsonSerializer.Serialize(
                new
                {
                    ok = true,
                    command = "security-4663-apply",
                    result = ceremonyResult
                },
                jsonOptions));
        return 0;
    }

    if (command == WindowsEventSourceReadinessCommand.Security4663Rollback)
    {
        var ceremonyResult = Security4663ReadinessCeremony.Rollback(
            new NativeSecurity4663CeremonyStore());
        Console.WriteLine(
            JsonSerializer.Serialize(
                new
                {
                    ok = true,
                    command = "security-4663-rollback",
                    result = ceremonyResult
                },
                jsonOptions));
        return 0;
    }

    if (command == WindowsEventSourceReadinessCommand.Security4663Exercise)
    {
        var ceremonyResult = Security4663ReadinessCeremony.Exercise(
            new NativeSecurity4663CeremonyStore());
        Console.WriteLine(
            JsonSerializer.Serialize(
                new
                {
                    ok = true,
                    command = "security-4663-exercise",
                    result = ceremonyResult
                },
                jsonOptions));
        return 0;
    }

    if (command == WindowsEventSourceReadinessCommand.Security4663OneShotPlan)
    {
        var oneShotPlan = Security4663OneShotMachinePlan.BuildPlan();
        Security4663OneShotMachinePlan.ValidatePlan(oneShotPlan);
        Console.WriteLine(
            JsonSerializer.Serialize(
                new
                {
                    ok = true,
                    command = "security-4663-one-shot-plan",
                    result = oneShotPlan
                },
                jsonOptions));
        return 0;
    }

    var result = WindowsEventSourceReadiness.Check(
        new NativeWindowsEventLogMetadataReader());
    Console.WriteLine(
        JsonSerializer.Serialize(
            new
            {
                ok = true,
                command = "source-readiness-check",
                result
            },
            jsonOptions));
    return result.Ready ? 0 : 2;
}
catch (InvalidDataException error)
{
    Console.Error.WriteLine(error.Message);
    return 2;
}
catch (Exception)
{
    Console.Error.WriteLine("SENSOR_SOURCE_READINESS_FAILED");
    return 3;
}
