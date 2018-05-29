using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.CommandLineUtils;

namespace DeveloperProxy
{
    public static class Program
    {
        private static int Main(string[] args)
        {
            var app = new CommandLineApplication
            {
                Name = Assembly.GetEntryAssembly().GetName().Name,
                Description = "TCP proxy service for development purposes."
            };

            // Specify the help option
            app.HelpOption("-?|--help");

            // Add some options
            var optionListenAll = app.Option("-a|--listen-all", "Listen on all IP endpoints.", CommandOptionType.NoValue);
            var optionListenEndpoint = app.Option("-e|--listen-endpoint<ip-address>", "Listen on the specific IP endpoint", CommandOptionType.MultipleValue);
            var optionDecryptSsl = app.Option("-d|--decrypt-ssl", "Decrypt the remote SSL stream", CommandOptionType.NoValue);
            var optionSslIdentification = app.Option("-s|--ssl-identification", "Decrypt the remote SSL stream", CommandOptionType.SingleValue);
            var optionIgnoreCertError = app.Option("-i|--ignore-certificate-errors", "Ignore any certificate errors", CommandOptionType.NoValue);
            var optionUseCertificate = app.Option("-c|--use-certificate", "Use the specified certificate", CommandOptionType.SingleValue);
            var optionCertificatePassword = app.Option("--certificate-password", "Use the specified certificate password", CommandOptionType.SingleValue);
            var optionLocalPort = app.Option("-l|--local-port", "Expose the service on the specified local port", CommandOptionType.SingleValue);
            var optionHost = app.Option("-r|--remote-host", "Connect to the service on the specified remote host/port", CommandOptionType.MultipleValue);
            var optionConnectTimeout = app.Option("-t|--connect-timeout", "Use the specified connection time-out (ms)", CommandOptionType.SingleValue);

            app.OnExecute(() => {
                // Determine the IP end-points where to listen to
                var ipAddresses = optionListenAll.HasValue() ? new[] {IPAddress.Any} : (GetIpsOption(optionListenEndpoint) ?? new[]{IPAddress.Loopback});

                // Determine the endpoints
                var localPort = GetNumericOption(optionLocalPort, 0);
                var connectTimeout = TimeSpan.FromMilliseconds(GetNumericOption(optionConnectTimeout, 5000));
                var hostnames = optionHost.Values.Any() ? GetHostsOptions(optionHost) : new [] { new HostAndPort("localhost") };
                var sslIdentification =  optionSslIdentification.HasValue() ?  optionSslIdentification.Value() : null;

                // Load the certificate (if specified)
                X509Certificate2 certificate = null;
                if (optionUseCertificate.HasValue())
                {
                    var fileName = optionUseCertificate.Value();
                    var password = optionCertificatePassword.HasValue() ? optionCertificatePassword.Value() : null;

                    certificate = new X509Certificate2(fileName, password);

                    if (!certificate.HasPrivateKey)
                        throw new Exception("Certificate doesn't have a private key.");
                }

                // Create all the listeners
                var listeners = ipAddresses.Select(ip => new IpListener(new IPEndPoint(ip, localPort), hostnames.ToArray(), connectTimeout, sslIdentification)
                {
                    DecryptSsl = optionDecryptSsl.HasValue(),
                    IgnoreCertificateErrors = optionIgnoreCertError.HasValue(),
                    Certificate = certificate
                }).ToList();

                // Start all listeners
                foreach (var listener in listeners)
                    listener.Start();

                // Keep running until the task is cancelled
                WaitForCtrlC();
                
                // Dispose all listeners
                foreach (var listener in listeners)
                    listener.Dispose();

                return 0;
            });

            return app.Execute(args);
        }

        private static int GetNumericOption(CommandOption option, int defaultValue)
        {
            if (!option.HasValue())
                return defaultValue;
            var value = option.Value();
            if (!int.TryParse(value, out var result))
                throw new Exception($"Option '{option.LongName}' has invalid numerical value '{option.Value()}'");
            return result;
        }

        private static IEnumerable<IPAddress> GetIpsOption(CommandOption option)
        {
            if (!option.HasValue())
                return null;
            return option.Values.Select(ip =>
            {
                if (!IPAddress.TryParse(ip, out var result))
                    throw new Exception($"Option '{option.LongName}' has invalid IP value '{ip}'");
                return result;
            });
        }

        private static IEnumerable<HostAndPort> GetHostsOptions(CommandOption option)
        {
            if (!option.HasValue())
                return null;
            return option.Values.Select(hap =>
            {
                var parts = hap.Split(':');
                if (parts.Length == 0)
                    return new HostAndPort(hap);
                if (parts.Length == 2 && int.TryParse(parts[1], out var port))
                    return new HostAndPort(parts[0], port);
                throw new Exception($"Option '{option.LongName}' has invalid host/port specification '{hap}'");
            });
        }

        private static void WaitForCtrlC()
        {
            var taskCompleted = new TaskCompletionSource<bool>();
            Console.CancelKeyPress += (sender, eventArgs) => taskCompleted.TrySetResult(true);
            taskCompleted.Task.Wait();
        }
    }
}