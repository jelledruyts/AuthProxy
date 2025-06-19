using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace AuthProxy.ReverseProxy.Infrastructure;

// Makes the base path of controllers configurable.
// See https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/routing#use-application-model-to-customize-attribute-routes
public class ApiRoutingConvention : IControllerModelConvention
{
    public const string Placeholder = "[basepath]";
    private readonly string? basePath;

    public ApiRoutingConvention(string? basePath)
    {
        this.basePath = basePath;
    }

    public void Apply(ControllerModel controller)
    {
        var routeAttribute = controller.Selectors.FirstOrDefault(s => s.AttributeRouteModel != null);
        if (routeAttribute?.AttributeRouteModel?.Template != null)
        {
            routeAttribute.AttributeRouteModel.Template = routeAttribute.AttributeRouteModel.Template.Replace(Placeholder, this.basePath, StringComparison.OrdinalIgnoreCase);
        }
    }
}