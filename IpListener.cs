using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DeveloperProxy
{
    public class IpListener : IDisposable
    {
        private readonly TcpListener _tcpListener;
        private readonly string _remoteHost;
        private readonly int _remotePort;
        private readonly CancellationTokenSource _ctsStop = new CancellationTokenSource();

        public IpListener(IPEndPoint localEndPoint, string remoteHost, int remotePort)
        {
            _tcpListener = new TcpListener(localEndPoint);
            _remoteHost = remoteHost;
            _remotePort = remotePort;
        }

        public bool DecryptSsl { get; set; }
        public bool IgnoreCertificateErrors { get; set; }
        public X509Certificate Certificate { get; set; }

        public void Dispose()
        {
            // Cancel all tasks and dispose
            _ctsStop?.Cancel();
            _ctsStop?.Dispose();
        }

        public async void Start()
        {
            _tcpListener.Start();
            Console.WriteLine($"Listening on {_tcpListener.LocalEndpoint}.");

            try
            {
                while (!_ctsStop.IsCancellationRequested)
                {
                    var socket = await _tcpListener.AcceptSocketAsync().ConfigureAwait(false);
                    HandleConnection(socket, _ctsStop.Token);
                }
            }
            catch (OperationCanceledException)
            {
                // Expected
            }
        }

        private async void HandleConnection(Socket socket, CancellationToken cancellationToken)
        {
            const int copyBlockSize = 64 * 1024;

            // Obtain both streams
            using (Stream localStream = new NetworkStream(socket, true))
            {
                // Encrypt use SSL
                if (Certificate != null)
                {
                    var localSslStream = new SslStream(localStream);
                    await localSslStream.AuthenticateAsServerAsync(Certificate).ConfigureAwait(false);
                }

                // Connect to the remote endpoint
                using (var tcpClient = new TcpClient())
                {
                    // Dispose the TCP client when the operation is cancelled
                    cancellationToken.Register(() => tcpClient.Dispose());

                    // Attempt to connect
                    await tcpClient.ConnectAsync(_remoteHost, _remotePort).ConfigureAwait(false);
                    var remoteStream = (Stream)tcpClient.GetStream();

                    if (DecryptSsl)
                    {
                        // Create the SSL stream with certificate validation
                        var remoteSslStream = new SslStream(remoteStream, false, (sender, certificate, chain, errors) =>
                        {
                            // No need for checking if there are no errors
                            if (errors == SslPolicyErrors.None)
                                return true;

                            // Log warning
                            Console.WriteLine($"Certificate with subject '{certificate.Subject}' has error {errors}.");
                            return IgnoreCertificateErrors;
                        });
                        await remoteSslStream.AuthenticateAsClientAsync(_remoteHost);

                        // Use the SSL stream
                        remoteStream = remoteSslStream;
                    }

                    // Wait until the streams have completed
                    await Task.WhenAny(
                        localStream.CopyToAsync(remoteStream, copyBlockSize, cancellationToken),
                        remoteStream.CopyToAsync(localStream, copyBlockSize, cancellationToken)).ConfigureAwait(false);
                }
            }
        }
    }
}