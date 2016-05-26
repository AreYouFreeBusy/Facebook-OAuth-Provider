// Copyright (c) Microsoft Open Technologies, Inc. See LICENSE file for more information.

using System;
using System.Collections.Generic;
using Microsoft.Owin;

namespace Owin.Security.Providers.Facebook
{
    /// <summary>
    /// Provides helper methods for processing requests.
    /// </summary>
    public static class WebHelpers
    {
        /// <summary>
        /// Parses an HTTP form body.
        /// </summary>
        /// <param name="text">The HTTP form body to parse.</param>
        public static IFormCollection ParseForm(string text)
        {
            IDictionary<string, string[]> form = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            var accumulator = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            ParseDelimited(text, new[] { '&' }, AppendItemCallback, accumulator);
            foreach (var kv in accumulator)
            {
                form.Add(kv.Key, kv.Value.ToArray());
            }
            return new FormCollection(form);
        }

        internal static void ParseDelimited(string text, char[] delimiters, Action<string, string, object> callback, object state)
        {
            int textLength = text.Length;
            int equalIndex = text.IndexOf('=');
            if (equalIndex == -1)
            {
                equalIndex = textLength;
            }
            int scanIndex = 0;
            while (scanIndex < textLength)
            {
                int delimiterIndex = text.IndexOfAny(delimiters, scanIndex);
                if (delimiterIndex == -1)
                {
                    delimiterIndex = textLength;
                }
                if (equalIndex < delimiterIndex)
                {
                    while (scanIndex != equalIndex && char.IsWhiteSpace(text[scanIndex]))
                    {
                        ++scanIndex;
                    }
                    string name = text.Substring(scanIndex, equalIndex - scanIndex);
                    string value = text.Substring(equalIndex + 1, delimiterIndex - equalIndex - 1);
                    callback(
                        Uri.UnescapeDataString(name.Replace('+', ' ')),
                        Uri.UnescapeDataString(value.Replace('+', ' ')),
                        state);
                    equalIndex = text.IndexOf('=', delimiterIndex);
                    if (equalIndex == -1)
                    {
                        equalIndex = textLength;
                    }
                }
                scanIndex = delimiterIndex + 1;
            }
        }

        private static readonly Action<string, string, object> AppendItemCallback = (name, value, state) =>
        {
            var dictionary = (IDictionary<string, List<String>>)state;

            List<string> existing;
            if (!dictionary.TryGetValue(name, out existing))
            {
                dictionary.Add(name, new List<string>(1) { value });
            }
            else
            {
                existing.Add(value);
            }
        };
    }
}