﻿using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace SoftServeProject3.Api.Utils;

class GetUserContractResolver : DefaultContractResolver
{
    protected override IList<JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
    {
        IList<JsonProperty> props = base.CreateProperties(type, memberSerialization);
        return props.Where(p => (p.PropertyName != "_id" && p.PropertyName != "password" && p.PropertyName != "isEmailConfirmed")).ToList();
    }
}