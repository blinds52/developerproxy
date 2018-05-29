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
        private readonly object _sync = new object();
        private readonly TcpListener _tcpListener;
        private readonly HostAndPort[] _remoteHosts;
        private readonly TimeSpan _connectTimeout;
        private readonly string _sslIdentification;
        private readonly CancellationTokenSource _ctsStop = new CancellationTokenSource();
        private int _hostIndex;

        public IpListener(IPEndPoint localEndPoint, HostAndPort[] remoteHosts, TimeSpan connectTimeout, string sslIdentification = null)
        {
            _tcpListener = new TcpListener(localEndPoint);
            _remoteHosts = remoteHosts;
            _connectTimeout = connectTimeout;
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

        private async Task<Stream> ConnectAsync(Socket socket, CancellationToken cancellationToken)
        {
            int baseHostIndex;
            lock (_sync)
            {
                baseHostIndex = _hostIndex++ % _remoteHosts.Length;
            }

            for (var i = 0; i < _remoteHosts.Length; ++i)
            {
                var host = _remoteHosts[(baseHostIndex + i) % _remoteHosts.Length];

                var tcpClient = new TcpClient();
                using (var timeoutCancellationTokenSource = new CancellationTokenSource(_connectTimeout))
                using (var linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(timeoutCancellationTokenSource.Token, cancellationToken))
                using (linkedTokenSource.Token.Register(() => tcpClient.Dispose()))
                {
                    try
                    {
                        await tcpClient.ConnectAsync(host.Hostname, host.Port).ConfigureAwait(false);
                        Console.WriteLine($"[{socket.RemoteEndPoint} -> {socket.LocalEndPoint}] - Connected to {host}");

                        var remoteStream = (Stream) tcpClient.GetStream();
                        if (DecryptSsl)
                        {
                            // Create the SSL stream with certificate validation
                            var remoteSslStream = new SslStream(remoteStream, false,
                                (sender, certificate, chain, errors) =>
                                {
                                    // No need for checking if there are no errors
                                    if (errors == SslPolicyErrors.None)
                                        return true;

                                    // Log warning
                                    Console.WriteLine($"[{socket.RemoteEndPoint} -> {socket.LocalEndPoint}] - Certificate with subject '{certificate.Subject}' has error {errors}.");
                                    return IgnoreCertificateErrors;
                                });
                            await remoteSslStream.AuthenticateAsClientAsync(_sslIdentification ?? host.Hostname);

                            // Use the SSL stream
                            remoteStream = remoteSslStream;
                        }

                        return remoteStream;
                    }
                    catch (Exception exc) when (!timeoutCancellationTokenSource.IsCancellationRequested)
                    {
                        Console.WriteLine($"[{socket.RemoteEndPoint} -> {socket.LocalEndPoint}] - Unable to connect to {host}: {exc.Message}");
                        tcpClient.Dispose();
                    }
                    catch
                    {
                        Console.WriteLine($"[{socket.RemoteEndPoint} -> {socket.LocalEndPoint}] - Timeout while connecting to '{host}' within {Math.Round(_connectTimeout.TotalMilliseconds)}ms");
                        tcpClient.Dispose();
                    }
                }
            }

            Console.WriteLine($"[{socket.LocalEndPoint}] - Cannot find a host to connect to.");
            return null;
        }

        private async void HandleConnection(Socket socket, CancellationToken cancellationToken)
        {
            const int copyBlockSize = 64 * 1024;

            // Log the connection that we have received
            Console.WriteLine($"[{socket.RemoteEndPoint} -> {socket.LocalEndPoint}] - Accepted connection.");
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
                var remoteStream = await ConnectAsync(socket, cancellationToken).ConfigureAwait(false);
                if (remoteStream == null)
                    return;

                // Wait until the streams have completed
                try
                {
                    await Task.WhenAny(
                            localStream.CopyToAsync(remoteStream, copyBlockSize, cancellationToken),
                            remoteStream.CopyToAsync(localStream, copyBlockSize, cancellationToken))
                        .ConfigureAwait(false);
                }
                catch (Exception exc)
                {
                    // Expected to fail sometimes
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(exc.ToString());
                    Console.ResetColor();
                }

                // Log warning
                Console.WriteLine($"[{socket.RemoteEndPoint} -> {socket.LocalEndPoint}] - Closed connection ({swConnection.ElapsedMilliseconds}ms).");
            }
        }
    }
}