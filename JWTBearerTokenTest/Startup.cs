using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Text;

namespace JWTBearerTokenTest
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.Configure<JWTBearerTokenSettings>(Configuration.GetSection("JWTBearerTokenSettings"));

            JWTBearerTokenSettings jwtSettings = Configuration.GetSection("JWTBearerTokenSettings").Get<JWTBearerTokenSettings>();
            services.AddHttpClient("Token4P", client =>
            {
                client.BaseAddress = new Uri(jwtSettings.Audience);
                byte[] byteArray = Encoding.ASCII.GetBytes($"{jwtSettings.ClientId}:{jwtSettings.ClientSecret}");
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));
            });
                
            string Uri4P = Configuration.GetValue<string>("Uri4P");
            services.AddHttpClient("4P", client =>
            {
                client.BaseAddress = new Uri(Uri4P);
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
