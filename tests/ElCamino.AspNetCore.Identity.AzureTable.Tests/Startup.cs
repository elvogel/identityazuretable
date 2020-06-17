// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.

using ElCamino.AspNetCore.Identity.AzureTable.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using IdentityUser = ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityUser;

namespace ElCamino.AspNetCore.Identity.AzureTable.Tests
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            // Setup configuration sources.
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("config.json")
                .AddJsonFile($"config.{env.EnvironmentName}.json", optional: true);

            configuration.AddEnvironmentVariables();
            Configuration = configuration.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddDataProtection();

            // Add Identity services to the services container.
            services.AddIdentityCore<IdentityUser>((config) =>
            {

            })
            //.AddEntityFrameworkStores<ApplicationDbContext>()
            .AddAzureTableStores<IdentityCloudContext>(() => new IdentityConfiguration()
            {
                StorageConnectionString = Configuration.GetValue<string>("IdentityAzureTable:identityConfiguration:storageConnectionString")
            })
            .AddDefaultTokenProviders();

            // Add MVC services to the services container.
            //services.AddMvc();

        }

        // Configure is called after ConfigureServices is called.
        public void Configure(IApplicationBuilder app)
        {
            // Add cookie-based authentication to the request pipeline.
            app.UseAuthentication();
        }
    }
}
