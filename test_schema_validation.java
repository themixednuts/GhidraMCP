// Simple test to validate our schema output matches Google AI API specification
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchema;

public class TestSchemaValidation {
    public static void main(String[] args) {
        // Test enum schema as per spec example:
        // {type:STRING, format:enum, enum:["EAST", "NORTH", "SOUTH", "WEST"]}
        JsonSchema enumSchema = JsonSchemaBuilder.string()
            .enumValues("EAST", "NORTH", "SOUTH", "WEST")
            .build();

        System.out.println("Enum Schema:");
        System.out.println(enumSchema.toJsonString().orElse("{}"));

        // Test complex object schema
        JsonSchema userSchema = JsonSchemaBuilder.object()
            .title("User")
            .description("Represents a user in the system")
            .property("id", JsonSchemaBuilder.integer().minimum(1).description("Unique identifier"), true)
            .property("name", JsonSchemaBuilder.string().minLength(1).maxLength(50).description("User's full name"), true)
            .property("email", JsonSchemaBuilder.string().pattern("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$").description("User's email address"))
            .property("tags", JsonSchemaBuilder.array()
                .items(JsonSchemaBuilder.string().description("A tag string"))
                .minItems(0)
                .maxItems(10)
                .description("Optional tags for the user"))
            .minProperties(2)
            .propertyOrdering("id", "name", "email", "tags")
            .build();

        System.out.println("\nUser Schema:");
        System.out.println(userSchema.toJsonString().orElse("{}"));
    }
}