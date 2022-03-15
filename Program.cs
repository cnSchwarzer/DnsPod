// See https://aka.ms/new-console-template for more information

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using DnsPod;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

HttpClient.DefaultProxy = new WebProxy();

var factory = LoggerFactory.Create(builder => {
    builder.AddSimpleConsole(o => {
        o.IncludeScopes = true;
        o.TimestampFormat = "HH:mm:ss ";
        o.SingleLine = true;
    });
    builder.AddFile("logs/zbot-{Date}.log", LogLevel.Trace);
    builder.SetMinimumLevel(
        LogLevel.Trace
    );
});
var logger = factory.CreateLogger("DnsPod");

logger.LogInformation("DnsPod");
logger.LogInformation("Network Interface List");
var allNetworkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
foreach (var (ni, i) in allNetworkInterfaces.Select((a, b) => (a, b))) {
    logger.LogInformation($"{i}. {ni.Name} ({ni.Description})");
}

HttpClient GetHttpClient(IPAddress address) {
    if (IPAddress.Any.Equals(address))
        return new HttpClient();

    var handler = new SocketsHttpHandler();

    handler.ConnectCallback = async (context, cancellationToken) => {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try {
            socket.Bind(new IPEndPoint(address, 0));
        } catch (Exception ex) {
            logger.LogError(ex, "Bind specific NIC failed. Fallback to IPAddress.Any");
            socket.Bind(new IPEndPoint(IPAddress.Any, 0));
        }
        socket.NoDelay = true;

        try {
            await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);

            return new NetworkStream(socket, true);
        } catch {
            socket.Dispose();

            throw;
        }
    };

    return new HttpClient(handler);
}

if (!File.Exists("./config.json")) {
    logger.LogInformation("./config.json not found. Generating default config.");
    File.WriteAllText("./config.json",
        JsonConvert.SerializeObject(new Config {
            Records = new List<Record>
                {new() {Domain = "example.com", SubDomain = "ex", Types = new List<string> {"A", "AAAA"}}}
        }, Formatting.Indented));
    return;
}

var config = JsonConvert.DeserializeObject<Config>(File.ReadAllText("./config.json"));

async Task<string> GetPublicIp(IPAddress address) {
    using var http = GetHttpClient(address);
    return await http.GetStringAsync(
        $"https://api{(address.AddressFamily == AddressFamily.InterNetwork ? "4" : "6")}.ipify.org/");
}

async Task<dynamic> GetRecordList(IPAddress address, string domain, string subDomain, string type) {
    using var http = GetHttpClient(address);
    var data =
        $"login_token={config.Id},{config.Token}&format=json&domain={domain}&sub_domain={subDomain}&record_type={type}";
    var resp = await http.PostAsync("https://dnsapi.cn/Record.List",
        new StringContent(data, Encoding.UTF8, "application/x-www-form-urlencoded"));
    return JObject.Parse(await resp.Content.ReadAsStringAsync());
}

async Task<dynamic> UpdateRecord(IPAddress address, string domain, string recordId, string subDomain, string record) {
    using var http = GetHttpClient(address);
    var data =
        $"login_token={config.Id},{config.Token}&format=json&domain={domain}&sub_domain={subDomain}&record_id={recordId}&value={record}&record_line=默认";
    var resp = await http.PostAsync("https://dnsapi.cn/Record.Ddns",
        new StringContent(data, Encoding.UTF8, "application/x-www-form-urlencoded"));
    return JObject.Parse(await resp.Content.ReadAsStringAsync());
}

while (true) {
    try {
        allNetworkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
        foreach (var record in config.Records) {
            logger.LogInformation($"Updating {record.SubDomain}.{record.Domain}");

            if (record.Types.Contains("A")) {
                var bind = IPAddress.Any;
                if (!string.IsNullOrEmpty(record.NicName)) {
                    var nic = allNetworkInterfaces.FirstOrDefault(a => a.Name == record.NicName);
                    var v4 = nic.GetIPProperties().UnicastAddresses
                        .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
                    if (v4 == null) {
                        logger.LogInformation($"{nic.Name} ({nic.Description}) has no IPv4 address.");
                        continue;
                    }
                    bind = v4.Address;
                }
                var ip = await GetPublicIp(bind);
                logger.LogInformation($"Fetched IPv4: {ip}");

                var recordList = await GetRecordList(IPAddress.Any, record.Domain, record.SubDomain, "A");
                if (recordList.status.code != 1) {
                    logger.LogInformation($"Get {record.SubDomain}.{record.Domain} A record failed.");
                    continue;
                }

                var r = recordList.records[0];
                var recordId = r.id;

                var ret = await UpdateRecord(IPAddress.Any, record.Domain, recordId, record.SubDomain, ip);
                if (ret.status.code != 1) {
                    logger.LogInformation($"Update {record.SubDomain}.{record.Domain} A record failed.");
                    continue;
                }

                logger.LogInformation($"Updated IPv4.");
            }

            if (record.Types.Contains("AAAA")) {
                var bind = IPAddress.Any;
                if (!string.IsNullOrEmpty(record.NicName)) {
                    var nic = allNetworkInterfaces.FirstOrDefault(a => a.Name == record.NicName);
                    var v6 = nic.GetIPProperties().UnicastAddresses
                        .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6);
                    if (v6 == null) {
                        logger.LogInformation($"{nic.Name} ({nic.Description}) has no IPv6 address.");
                        continue;
                    }
                    bind = v6.Address;
                }
                var ip = await GetPublicIp(bind);
                logger.LogInformation($"Fetched IPv6: {ip}");

                var recordList = await GetRecordList(IPAddress.Any, record.Domain, record.SubDomain, "AAAA");
                if (recordList.status.code != 1) {
                    logger.LogInformation($"Get {record.SubDomain}.{record.Domain} AAAA record failed.");
                    continue;
                }

                var r = recordList.records[0];
                var recordId = r.id;

                var ret = await UpdateRecord(IPAddress.Any, record.Domain, recordId, record.SubDomain, ip);
                if (ret.status.code != 1) {
                    logger.LogInformation($"Update {record.SubDomain}.{record.Domain} AAAA record failed.");
                    continue;
                }

                logger.LogInformation($"Updated IPv6.");
            }
        }
    } catch (Exception ex) {
        logger.LogError(ex, "Error");
    } 
    await Task.Delay(TimeSpan.FromSeconds(config.Interval));
}