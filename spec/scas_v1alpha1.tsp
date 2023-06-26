// https://microsoft.github.io/cadl/
import "@typespec/rest";
import "@typespec/openapi3";

using TypeSpec.Http;

@service({
    title: "sample service",
    version: "v1alpha1",
})
@route("/scas")
@tag("scas")
@tag("v1alpha1")
namespace scas;

model Project {
    @key("id")
    id: string;
    name: string;
    @format("date-time") // RFC3339Z
    created?: string;
}

@route("/projects")
interface Projects {
    @post
    create(): Project;
    @get list(): Project[];
}
