using System.Net.Http.Headers;
using IdentityModel.Client;
using Spectre.Console;

var client = new HttpClient();
var token = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
{
    Address = "https://localhost:5001/connect/token",
    ClientId = "client",
    ClientSecret = "secret"
});

AnsiConsole.Write(new Rule("[green]Fetched Token[/]"));
Console.WriteLine(token.AccessToken + Environment.NewLine + Environment.NewLine);

var apiRequest = new HttpRequestMessage(HttpMethod.Get, "https://localhost:7104/demo");
apiRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
var apiResponse = await client.SendAsync(apiRequest);
apiResponse.EnsureSuccessStatusCode();

var responseBody = await apiResponse.Content.ReadAsStringAsync();
AnsiConsole.Write(new Rule("[green]API Response[/]"));
Console.WriteLine(responseBody);