using MongoDB.Bson;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

public class ObjectIdJsonConverter : JsonConverter
{
    public override bool CanConvert(Type objectType)
    {
        return objectType == typeof(ObjectId);
    }

    public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
    {
        var token = JToken.Load(reader);
        return new ObjectId(token.ToObject<string>());
    }

    public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
    {
        if (value is ObjectId objectId)
        {
            serializer.Serialize(writer, objectId.ToString());
        }
    }
}