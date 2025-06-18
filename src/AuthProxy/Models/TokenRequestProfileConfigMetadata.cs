namespace AuthProxy.Models;

// This file is shared with the AuthProxy.Client project, so that models can be
// maintained in one place, while still avoiding the projects to have a runtime
// dependency on each other.

public class TokenRequestProfileConfigMetadata
{
    public string? Id { get; set; }
    public string? IdentityProvider { get; set; }
}