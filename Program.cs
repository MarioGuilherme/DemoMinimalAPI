using DemoMinimalAPI.Data;
using DemoMinimalAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using MiniValidation;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Jwt.Model;
using NetDevPack.Identity.Model;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

#region Configure Services
builder.Services.AddDbContext<MinimalContextDb>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentityEntityFrameworkContextConfiguration(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
    b => b.MigrationsAssembly("DemoMinimalAPI"))
);

builder.Services.AddIdentityConfiguration();
builder.Services.AddJwtConfiguration(builder.Configuration, "AppSettings");

builder.Services.AddAuthorization(options => {
    options.AddPolicy("DeleteSupplier", policy => policy.RequireClaim("DeleteSupplier"));
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(config => {
    config.SwaggerDoc("v1", new() {
        Title = "Minimal API Sample",
        Description = "Developed by Eduardo Pires - Owner @ desenvolvedor.io",
        Contact = new() { Name = "Eduardo Pires", Email = "contato@eduardopires.net.br" },
        License = new() { Name = "MIT", Url = new("https://opensource.org/licenses/MIT") }
    });

    config.AddSecurityDefinition("Bearer", new() {
        Description = "Insira o token JWT desta maneira: Bearer {seu token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    config.AddSecurityRequirement(new() {
        {
            new() {
                Reference = new() {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

WebApplication app = builder.Build();
#endregion

#region Configure Pipeline
if (app.Environment.IsDevelopment()) {
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthConfiguration();
app.UseHttpsRedirection();

MapActions(app);

app.Run();
#endregion

#region Actions
void MapActions(WebApplication app) {
    app.MapPost("/register", [AllowAnonymous] async (
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOptions<AppJwtSettings> appJwtSettings,
        RegisterUser registerUser
    ) => {
        if (registerUser is null)
            return Results.BadRequest("Usuário não informado");

        if (!MiniValidator.TryValidate(registerUser, out IDictionary<string, string[]> errors))
            return Results.ValidationProblem(errors);

        IdentityUser user = new() {
            UserName = registerUser.Email,
            Email = registerUser.Email,
            EmailConfirmed = true
        };

        IdentityResult result = await userManager.CreateAsync(user, registerUser.Password);

        if (!result.Succeeded)
            return Results.BadRequest(result.Errors);

        UserResponse jwt = new JwtBuilder()
                    .WithUserManager(userManager)
                    .WithJwtSettings(appJwtSettings.Value)
                    .WithEmail(user.Email)
                    .WithJwtClaims()
                    .WithUserClaims()
                    .WithUserRoles()
                    .BuildUserResponse();

        return Results.Ok(jwt);
    }).ProducesValidationProblem()
     .Produces(StatusCodes.Status200OK)
     .Produces(StatusCodes.Status400BadRequest)
     .WithName("RegisterUser")
     .WithTags("User");

    app.MapPost("/login", [AllowAnonymous] async (
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOptions<AppJwtSettings> appJwtSettings,
        LoginUser loginUser
    ) => {
        if (loginUser is null)
            return Results.BadRequest("Usuário não informado");
        
        if (!MiniValidator.TryValidate(loginUser, out IDictionary<string, string[]> errors))
            return Results.ValidationProblem(errors);
        
        SignInResult result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, true);
        
        if (result.IsLockedOut)
            return Results.BadRequest("Usuário bloqueado");
        
        if (!result.Succeeded)
            return Results.BadRequest("Usuário ou senha inválidos");
        
        UserResponse jwt = new JwtBuilder()
                    .WithUserManager(userManager)
                    .WithJwtSettings(appJwtSettings.Value)
                    .WithEmail(loginUser.Email)
                    .WithJwtClaims()
                    .WithUserClaims()
                    .WithUserRoles()
                    .BuildUserResponse();
        
        return Results.Ok(jwt);
    }).ProducesValidationProblem()
     .Produces(StatusCodes.Status200OK)
     .Produces(StatusCodes.Status400BadRequest)
     .WithName("LoginUser")
     .WithTags("User");

    app.MapGet("/supplier",
        [AllowAnonymous] async (MinimalContextDb context) => await context.Suppliers.ToListAsync()
    ).WithName("GetSuppliers")
     .WithTags("Supplier");

    app.MapGet("/supplier/{id}",
        async (
            Guid id,
            MinimalContextDb context
        ) => await context.Suppliers.FindAsync(id) is Supplier supplier
            ? Results.Ok(supplier)
            : Results.NotFound()
    ).Produces<Supplier>(StatusCodes.Status200OK)
     .Produces(StatusCodes.Status404NotFound)
     .WithName("GetSupplierById")
     .WithTags("Supplier");

    app.MapPost("/supplier",
        [Authorize] async (
            MinimalContextDb context,
            Supplier supplier
        ) => {
            if (!MiniValidator.TryValidate(supplier, out IDictionary<string, string[]> errors))
                return Results.ValidationProblem(errors);

            await context.Suppliers.AddAsync(supplier);
            int result = await context.SaveChangesAsync();
            return result > 0
                //? Results.Created($"/supplier/{supplier.Id}", supplier)
                ? Results.CreatedAtRoute("GetSupplierById", new { id = supplier.Id }, supplier)
                : Results.BadRequest("Houve um problema ao salvar o registro");
        }
    ).ProducesValidationProblem()
     .Produces<Supplier>(StatusCodes.Status201Created)
     .Produces(StatusCodes.Status400BadRequest)
     .WithName("PostSupplier")
     .WithTags("Supplier");

    app.MapPut("/supplier/{id}",
        [Authorize] async (
            Guid id,
            MinimalContextDb context,
            Supplier supplier
        ) => {
            Supplier? SupplierDataBase = await context.Suppliers.AsNoTracking().FirstOrDefaultAsync(supplier => supplier.Id == id);

            if (SupplierDataBase is null)
                return Results.NotFound();

            if (!MiniValidator.TryValidate(supplier, out IDictionary<string, string[]> errors))
                return Results.ValidationProblem(errors);

            context.Suppliers.Update(supplier);
            int result = await context.SaveChangesAsync();

            return result > 0
                ? Results.NoContent()
                : Results.BadRequest("Houve um problema ao salvar o registro");
        }
    ).ProducesValidationProblem()
     .Produces(StatusCodes.Status204NoContent)
     .Produces(StatusCodes.Status400BadRequest)
     .WithName("PutSupplier")
     .WithTags("Supplier");

    app.MapDelete("/supplier/{id}",
        [Authorize] async (
            Guid id,
            MinimalContextDb context
        ) => {
            Supplier? supplier = await context.Suppliers.FindAsync(id);

            if (supplier is null)
                return Results.NotFound();

            context.Suppliers.Remove(supplier);
            int result = await context.SaveChangesAsync();

            return result > 0
                ? Results.NoContent()
                : Results.BadRequest("Houve um problema ao salvar o registro");
        }
    ).Produces(StatusCodes.Status400BadRequest)
     .Produces(StatusCodes.Status204NoContent)
     .Produces(StatusCodes.Status404NotFound)
     .RequireAuthorization("DeleteSupplier")
     .WithName("DeleteSupplier")
     .WithTags("Supplier");
}
#endregion