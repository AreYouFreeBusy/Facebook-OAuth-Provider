//  Copyright 2015 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;

namespace Owin.Security.Providers.Facebook
{
    public static class FacebookAuthenticationExtensions
    {
        public static IAppBuilder UseFacebookAuthentication(this IAppBuilder app, FacebookAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(FacebookAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseFacebookAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            return app.UseFacebookAuthentication(new FacebookAuthenticationOptions
            {
                AppId = appId,
                AppSecret = appSecret
            });
        }
    }
}