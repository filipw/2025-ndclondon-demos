using SignalrServer;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSignalR();
builder.Services.AddCors(options =>
{
    options.AddPolicy("default",
        builder =>
        {
            builder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()
                .SetIsOriginAllowedToAllowWildcardSubdomains();
        });
});
var app = builder.Build();
app.UseCors("default");

app.MapHub<BlazorChatSampleHub>("/chat");
app.Run();