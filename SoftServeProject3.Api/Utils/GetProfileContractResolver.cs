using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace SoftServeProject3.Api.Utils;

class GetUserContractResolver : DefaultContractResolver
{
    protected override IList<JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
    {
        IList<JsonProperty> props = base.CreateProperties(type, memberSerialization);
        return props.Where(p => p.PropertyName is "username" or "photoUrl" or "faculty" or "name" or "description" or "subjects" or "social" or "schedule" or "Start" or "End" or "isProfilePrivate" or "friends").ToList();
    }
}