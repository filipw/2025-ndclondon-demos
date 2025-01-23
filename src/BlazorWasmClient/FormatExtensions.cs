namespace BlazorWasmClient
{
    public static class FormatExtensions
    {
        public static string PrettyPrint(this byte[] bytes)
        {
            var base64 = Convert.ToBase64String(bytes);
            return base64.Length > 50 ? $"{base64[..25]}...{base64[^25..]}" : base64;
        }
    }
}
