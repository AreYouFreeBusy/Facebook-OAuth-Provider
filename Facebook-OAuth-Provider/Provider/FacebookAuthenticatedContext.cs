//  Copyright 2015 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Facebook
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class FacebookAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="FacebookAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Facebook Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public FacebookAuthenticatedContext(
            IOwinContext context, JObject user, JObject permissions, string accessToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "id");
            Name = TryGetValue(user, "name");
            Link = TryGetValue(user, "link");
            UserName = TryGetValue(user, "username");
            Email = TryGetValue(user, "email");

            GrantedScope = TryGetPermissions(permissions);
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Facebook access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Facebook access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the Facebook user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        public string Link { get; private set; }

        /// <summary>
        /// Gets the Facebook username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Facebook email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the permissions that were granted by the user
        /// </summary>
        public IEnumerable<string> GrantedScope { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        private static List<string> TryGetPermissions(JObject permissions)
        {
            if (permissions["data"] == null) return null;

            var grantedScopes = new List<string>();
            foreach (var item in permissions["data"]) {
                if (item["status"] != null && item["status"].Value<string>() == "granted") {
                    grantedScopes.Add(item["permission"].Value<string>());
                }            
            }

            return grantedScopes;
        }
    }
}
