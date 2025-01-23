namespace SignalrServer
{
    internal class User
    {
        public string ConnectionId { get; set; }
        public string Username { get; set; }
        public byte[] PublicKey { get; set; }
    }
}