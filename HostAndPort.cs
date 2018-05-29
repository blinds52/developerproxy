namespace DeveloperProxy
{
    public struct HostAndPort
    {
        public string Hostname { get; }
        public int Port { get; }

        public HostAndPort(string hostname, int port = 80)
        {
            Hostname = hostname;
            Port = port;
        }

        public override string ToString() => $"{Hostname}:{Port}";
    }
}