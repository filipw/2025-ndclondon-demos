using Microsoft.AspNetCore.SignalR;
using System.Collections.Concurrent;

namespace SignalrServer
{
    public class BlazorChatSampleHub : Hub
    {
        private static readonly ConcurrentDictionary<string, User> Users = new ConcurrentDictionary<string, User>();

        public async Task GetAllUsers()
        {
            await Clients.Caller.SendAsync("AllUsers", Users.Select(u => u.Value).ToArray());
        }

        public async Task Join(string username, byte[] publicKey)
        {
            var user = new User
            {
                Username = username,
                ConnectionId = Context.ConnectionId,
                PublicKey = publicKey
            };

            if (Users.ContainsKey(username))
            {
                throw new Exception("User already joined!");
            }

            if (Users.TryAdd(username, user))
            {
                Console.WriteLine($"Added user {user.Username}");
                await Clients.Others.SendAsync("UserJoined", username, publicKey);
                await Clients.Caller.SendAsync("UserList", Users.Select(u => u.Value).ToArray());
            }
        }

        public async Task Negotiate(string username, byte[] encapsulatedSecret)
        {
            if (!Users.TryGetValue(username, out var targetUser))
            {
                throw new Exception("Target user not found!");
            }

            var sourceUser = Users.FirstOrDefault(u => u.Value.ConnectionId == Context.ConnectionId);
            if (sourceUser.Value == null)
            {
                throw new Exception("Source user not found!");
            }

            await Clients.Client(targetUser.ConnectionId).SendAsync("IncomingNegotiation", sourceUser.Value.Username, encapsulatedSecret);
        }

        public async Task DirectMessage(string username, byte[] encryptedDirectMessage)
        {
            if (!Users.TryGetValue(username, out var targetUser))
            {
                throw new Exception("Target user not found!");
            }

            var sourceUser = Users.FirstOrDefault(u => u.Value.ConnectionId == Context.ConnectionId);
            if (sourceUser.Value == null)
            {
                throw new Exception("Source user not found!");
            }

            await Clients.Client(targetUser.ConnectionId).SendAsync("IncomingDirectMessage", sourceUser.Value.Username, encryptedDirectMessage);
        }

        public override Task OnConnectedAsync()
        {
            Console.WriteLine($"{Context.ConnectionId} connected");
            return base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(Exception e)
        {
            Console.WriteLine($"Disconnected {e?.Message} {Context.ConnectionId}");
            var user = Users.FirstOrDefault(u => u.Value.ConnectionId == Context.ConnectionId);
            if (user.Value != null)
            {
                if (Users.TryRemove(user))
                {
                    Console.WriteLine($"Removed user {user.Value.Username}");
                }
            }

            await base.OnDisconnectedAsync(e);
        }
    }
}