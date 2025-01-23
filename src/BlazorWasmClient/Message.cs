namespace BlazorWasmClient
{
    public class Message
    {
        public Message(string body, bool own)
        {
            Body = body;
            Own = own;
        }

        public string Body { get; set; }
        public bool Own { get; set; }
    }
}
