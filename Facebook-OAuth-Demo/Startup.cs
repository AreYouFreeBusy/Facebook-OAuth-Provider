using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Facebook_OAuth_Demo.Startup))]
namespace Facebook_OAuth_Demo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
