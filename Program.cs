using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
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
            app.HelpOption("-?|-h|--help");

            // Add some options
            var optionListenAll = app.Option("-a|--listen-all", "Listen on all IP endpoints.", CommandOptionType.NoValue);
            var optionListenEndpoint = app.Option("-e|--listen-endpoint<ip-address>", "Listen on the specific IP endpoint", CommandOptionType.MultipleValue);
            var optionDecryptSsl = app.Option("-d|--decrypt-ssl", "Decrypt the remote SSL stream", CommandOptionType.NoValue);
            var optionIgnoreCertError = app.Option("-i|--ignore-certificate-errors", "Ignore any certificate errors", CommandOptionType.NoValue);
            var optionUseCertificate = app.Option("-c|--use-certificate", "Use the specified certificate", CommandOptionType.SingleValue);
            var optionCertificatePassword = app.Option("--certificate-password", "Use the specified certificate password", CommandOptionType.SingleValue);
            var optionLocalPort = app.Option("-l|--local-port", "Expose the service on the specified local port", CommandOptionType.SingleValue);
            var optionHost = app.Option("-h|--host", "Connect to the service on the specified host", CommandOptionType.SingleValue);
            var optionRemotePort = app.Option("-p|--remote-port", "Connect to the service on the specified port", CommandOptionType.SingleValue);

            app.OnExecute(() => {
                // Determine the IP end-points where to listen to
                IEnumerable<IPAddress> ipAddresses;
                if (optionListenAll.HasValue())
                    ipAddresses = new[] {IPAddress.Any};
                else if (optionListenEndpoint.HasValue())
                    ipAddresses = optionListenEndpoint.Values.Select(IPAddress.Parse);
                else
                    ipAddresses = GetIpAddresses(true);

                // Determine the endpoints
                var localPort = optionLocalPort.HasValue() ? int.Parse(optionLocalPort.Value()) : 0;
                var host = optionHost.HasValue() ? optionHost.Value() : null;
                var remotePort = optionRemotePort.HasValue() ? int.Parse(optionRemotePort.Value()) : 0;

                // Load the certificate (if specified)
                X509Certificate2 certificate = null;
                if (optionUseCertificate.HasValue())
                {
                    var password = optionCertificatePassword.HasValue() ? optionCertificatePassword.Value() : null;
                    certificate = new X509Certificate2(optionUseCertificate.Value(), password);
                    if (!certificate.HasPrivateKey)
                        throw new Exception("Certificate doesn't have a private key.");
                }

                // Create all the listeners
                var listeners = ipAddresses.Select(ip => new IpListener(new IPEndPoint(ip, localPort), host, remotePort)
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

        private static void WaitForCtrlC()
        {
            var taskCompleted = new TaskCompletionSource<bool>();
            Console.CancelKeyPress += (sender, eventArgs) => taskCompleted.TrySetResult(true);
            taskCompleted.Task.Wait();
        }

        private static IEnumerable<IPAddress> GetIpAddresses(bool localOnly)
        {
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!localOnly || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    var ipProperties = networkInterface.GetIPProperties();
                    foreach (var unicastAddress in ipProperties.UnicastAddresses)
                        yield return unicastAddress.Address;
                }
            }
        }
    }
}