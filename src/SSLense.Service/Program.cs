using Serilog;
using SSLense.Core;
using SSLense.Core.Config;
using SSLense.Service;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.File(
        Path.Combine(AppPaths.LogDirectory, "sslense-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        shared: true)
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddWindowsService(options => options.ServiceName = "SSLense");
    builder.Services.AddSerilog();
    builder.Services.AddSSLenseCore();
    builder.Services.AddHostedService<RenewalWorker>();
    await builder.Build().RunAsync();
}
catch (Exception exception)
{
    Log.Fatal(exception, "SSLense Renewal Service terminated unexpectedly");
}
finally
{
    await Log.CloseAndFlushAsync();
}
