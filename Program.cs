using DemoMinimalAPI.Data;
using DemoMinimalAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Model;

var builder = WebApplication.CreateBuilder(args);

#region Configure Services

builder.Services.AddIdentityEntityFrameworkContextConfiguration(
    options => options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        b => b.MigrationsAssembly("DemoMinimalAPI")
    )
);

builder.Services.AddDbContext<MinimalContextDB>(
    options => options.UseSqlServer(builder.Configuration.GetConnectionString("defaultConnection"))
);

builder.Services.AddIdentityConfiguration();
builder.Services.AddJwtConfiguration(builder.Configuration, "AppSettings");

builder.Services.AddAuthorization(options => {
    options.AddPolicy("ExcluirFornecedor", policy => policy.RequireClaim("ExcluirFornecedor"));
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => {
    c.SwaggerDoc("v1", new OpenApiInfo {
        Title = "Minimal API Sample",
        Description = "Developed by Eduardo Pires - Owner @ desenvolvedor.io",
        Contact = new OpenApiContact { Name = "Eduardo Pires", Email = "contato@eduardopires.net.br" },
        License = new OpenApiLicense { Name = "MIT", Url = new Uri("https://opensource.org/licenses/MIT") }
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme {
        Description = "Insira o token JWT desta maneira: Bearer {seu token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
        {
            new OpenApiSecurityScheme {
                Reference = new OpenApiReference {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();

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
    app.MapPost("/cadastro",
        [AllowAnonymous] async (
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            IOptions<AppJwtSettings> appJwtSettings,
            RegisterUser registerUser
        ) => {
            if (registerUser == null)
                return Results.BadRequest("Usuário não informado!");

            if (!MiniValidation.MiniValidator.TryValidate(registerUser, out var errors))
                return Results.ValidationProblem(errors);

            var user = new IdentityUser {
                UserName = registerUser.Email,
                Email = registerUser.Email,
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(user, registerUser.Password);

            if (!result.Succeeded)
                return Results.BadRequest(result.Errors);

            var jwt = new JwtBuilder()
                                .WithUserManager(userManager)
                                .WithJwtSettings(appJwtSettings.Value)
                                .WithEmail(user.Email)
                                .WithJwtClaims()
                                .WithUserClaims()
                                .WithUserRoles()
                                .BuildUserResponse();

            return Results.Ok(jwt);
        }
    ).ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("CadastroUsuario")
    .WithTags("Usuario");

    app.MapPost("/login",
        [AllowAnonymous] async (
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            IOptions<AppJwtSettings> appJwtSettings,
            LoginUser loginUser
        ) => {
            if (loginUser == null)
                return Results.BadRequest("Usu�rio n�o informado");

            if (!MiniValidation.MiniValidator.TryValidate(loginUser, out var errors))
                return Results.ValidationProblem(errors);

            var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, true);

            if (result.IsLockedOut)
                return Results.BadRequest("Usu�rio bloqueado");

            if (!result.Succeeded)
                return Results.BadRequest("Usu�rio ou senha inv�lidos");

            var jwt = new JwtBuilder()
                    .WithUserManager(userManager)
                    .WithJwtSettings(appJwtSettings.Value)
                    .WithEmail(loginUser.Email)
                    .WithJwtClaims()
                    .WithUserClaims()
                    .WithUserRoles()
                    .BuildUserResponse();

            Results.Ok(jwt);
        }
    ).ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("LoginUsuario")
    .WithTags("Usuario");

    app.MapGet("/fornecedor",
        [AllowAnonymous] async (MinimalContextDB context) => await context.Fornecedores.ToListAsync()
    ).WithName("GetFornecedores")
    .WithTags("Fornecedor");

    app.MapGet("/fornecedor/{id}",
        [Authorize] async (
            Guid id,
            MinimalContextDB context
        ) => await context.Fornecedores.FindAsync(id) is Fornecedor fornecedor ? Results.Ok(fornecedor) : Results.NotFound()
    ).Produces<Fornecedor>(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status404NotFound)
    .WithName("GetFornecedorPorId")
    .WithTags("Fornecedor");

    app.MapPost("/fornecedor",
        [Authorize] async (
            MinimalContextDB context,
            Fornecedor fornecedor
        ) => {
            if (!MiniValidation.MiniValidator.TryValidate(fornecedor, out var errors))
                return Results.ValidationProblem(errors);

            context.Fornecedores.Add(fornecedor);
            var result = await context.SaveChangesAsync();

            return result > 0
            // ? Results.Created($"/fornecedor/{fornecedor.Id}", fornecedor);
            ? Results.CreatedAtRoute("GetFornecedorPorId", new { id = fornecedor.Id })
            : Results.BadRequest("Houve um problema ao salvar o registro");
        }
    ).ProducesValidationProblem()
    .Produces<Fornecedor>(StatusCodes.Status201Created)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("PostFornecedor")
    .WithTags("Fornecedor");

    app.MapPut("/fornecedor/{id}",
        [Authorize] async (
            Guid id,
            MinimalContextDB context,
            Fornecedor fornecedor
        ) => {
            var fornecedorBanco = await context.Fornecedores
                                            .AsNoTracking<Fornecedor>()
                                            .FirstOrDefaultAsync
                                            (f => f.Id == id);

            if (fornecedorBanco == null)
                return Results.NotFound();

            if (!MiniValidation.MiniValidator.TryValidate(fornecedor, out var errors))
                return Results.ValidationProblem(errors);

            context.Fornecedores.Update(fornecedor);
            var result = await context.SaveChangesAsync();

            return result > 0
            ? Results.NoContent()
            : Results.BadRequest("Houve um problema ao salvar o registro");
        }
    ).ProducesValidationProblem()
    .Produces(StatusCodes.Status204NoContent)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("PutFornecedor")
    .WithTags("Fornecedor");

    app.MapDelete("/fornecedor/{id}",
        [Authorize] async (
            Guid id,
            MinimalContextDB context
        ) => {
            var fornecedor = await context.Fornecedores.FindAsync(id);

            if (fornecedor == null)
                return Results.NotFound();

            context.Fornecedores.Remove(fornecedor);
            var result = await context.SaveChangesAsync();

            return result > 0
            ? Results.NoContent()
            : Results.BadRequest("Houve um problema ao salvar o registro");
        }
    ).Produces(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status204NoContent)
    .Produces(StatusCodes.Status404NotFound)
    .RequireAuthorization("ExcluirFornecedor")
    .WithName("DeleteFornecedor")
    .WithTags("Fornecedor");
}

#endregion