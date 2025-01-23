namespace BlazorWasmClient
{
    public class User
    {
        public string Username { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] NegotiatedSharedSecret { get; set; }

        public List<Message> DirectMessages { get; set; } = new List<Message>();
    }
}
