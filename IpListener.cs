using System;
using System.Diagnostics;
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
        private readonly string _sslIdentification;
        private readonly CancellationTokenSource _ctsStop = new CancellationTokenSource();

        public IpListener(IPEndPoint localEndPoint, string remoteHost, int remotePort, string sslIdentification = null)
        {
            _tcpListener = new TcpListener(localEndPoint);
            _remoteHost = remoteHost;
            _remotePort = remotePort;
            _sslIdentification = sslIdentification;
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

            // Log the connection that we have received
            Console.WriteLine($"[{socket.LocalEndPoint}] - Accepted connection.");
            var swConnection = Stopwatch.StartNew();
                    
            // Obtain both streams
            using (var networkStream = new NetworkStream(socket, true))
            {
                Stream localStream;

                // Encrypt use SSL
                if (Certificate != null)
                {
                    var localSslStream = new SslStream(networkStream);
                    await localSslStream.AuthenticateAsServerAsync(Certificate).ConfigureAwait(false);
                    localStream = localSslStream;
                }
                else
                {
                    localStream = networkStream;
                }

                // Connect to the remote endpoint
                using (var tcpClient = new TcpClient())
                {
                    // Dispose the TCP client when the operation is cancelled
                    cancellationToken.Register(() => tcpClient.Dispose());

                    Stream remoteStream;
                    try
                    {
                        // Attempt to connect
                        await tcpClient.ConnectAsync(_remoteHost, _remotePort).ConfigureAwait(false);
                        remoteStream = (Stream)tcpClient.GetStream();
                    }
                    catch (Exception exc)
                    {
                        Console.WriteLine($"[{socket.LocalEndPoint}] - Unable to connect to {_remoteHost}:{_remotePort} ({swConnection.ElapsedMilliseconds}ms): {exc.Message}");
                        return;
                    }

                    // We're connected
                    Console.WriteLine($"[{socket.LocalEndPoint}] - Connected to {_remoteHost}:{_remotePort} ({swConnection.ElapsedMilliseconds}ms)");

                    if (DecryptSsl)
                    {
                        // Create the SSL stream with certificate validation
                        var remoteSslStream = new SslStream(remoteStream, false, (sender, certificate, chain, errors) =>
                        {
                            // No need for checking if there are no errors
                            if (errors == SslPolicyErrors.None)
                                return true;

                            // Log warning
                            Console.WriteLine($"[{socket.LocalEndPoint}] - Certificate with subject '{certificate.Subject}' has error {errors}.");
                            return IgnoreCertificateErrors;
                        });
                        await remoteSslStream.AuthenticateAsClientAsync(_sslIdentification ?? _remoteHost);

                        // Use the SSL stream
                        remoteStream = remoteSslStream;
                    }

                    // Wait until the streams have completed
                    try
                    {
                    await Task.WhenAny(
                        localStream.CopyToAsync(remoteStream, copyBlockSize, cancellationToken),
                        remoteStream.CopyToAsync(localStream, copyBlockSize, cancellationToken)).ConfigureAwait(false);
                    }
                    catch
                    {
                        // Expected to fail sometimes
                    }

                    // Log warning
                    Console.WriteLine($"[{socket.LocalEndPoint}] - Closed connection ({swConnection.ElapsedMilliseconds}ms).");
                }
            }
        }
    }
}
