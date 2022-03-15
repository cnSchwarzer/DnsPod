using Newtonsoft.Json;

namespace DnsPod;

public class Record {
    [JsonProperty("sub_domain")] public string SubDomain { get; set; }
    [JsonProperty("domain")] public string Domain { get; set; }
    [JsonProperty("types")] public List<string> Types { get; set; } = new();
    [JsonProperty("nic")] public int Nic { get; set; } = -1;
}

public class Config {
    [JsonProperty("id")] public string Id { get; set; } = "123456";
    [JsonProperty("token")] public string Token { get; set; } = ""; 
    [JsonProperty("records")] public List<Record> Records { get; set; } = new();
    [JsonProperty("interval")] public int Interval { get; set; } = 60;
}