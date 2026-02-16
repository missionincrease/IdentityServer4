// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Models;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using IdentityServer4.Configuration;

namespace IdentityServer4.Extensions
{
    /// <summary>
    /// Extensions for Token
    /// </summary>
    public static class TokenExtensions
    {
        /// <summary>
        /// Creates the default JWT payload.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="timeProvider">The time provider.</param>
        /// <param name="options">The options</param>
        /// <param name="logger">The logger.</param>
        /// <returns></returns>
        /// <exception cref="Exception">
        /// </exception>
        public static JwtPayload CreateJwtPayload(this Token token, TimeProvider timeProvider, IdentityServerOptions options, ILogger logger)
        {
            var now = timeProvider.GetUtcNow().UtcDateTime;
            var payload = new JwtPayload(
                token.Issuer,
                null,
                null,
                now,
                now.AddSeconds(token.Lifetime));

            foreach (var aud in token.Audiences)
            {
                payload.AddClaim(new Claim(JwtClaimTypes.Audience, aud));
            }

            var amrClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.AuthenticationMethod).ToArray();
            var scopeClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.Scope).ToArray();
            var jsonClaims = token.Claims.Where(x => x.ValueType == IdentityServerConstants.ClaimValueTypes.Json).ToList();

            // add cnf claim if present - use JsonElement for IdentityModel 7 compatibility (System.Text.Json);
            // JObject/Newtonsoft types are not serialized correctly when IdentityModel writes the JWT.
            if (token.Confirmation.IsPresent())
            {
                var cnfElement = JsonSerializer.Deserialize<JsonElement>(token.Confirmation);
                payload.Add(JwtClaimTypes.Confirmation, cnfElement);
            }

            var normalClaims = token.Claims
                .Except(amrClaims)
                .Except(jsonClaims)
                .Except(scopeClaims);

            payload.AddClaims(normalClaims);

            // scope claims
            if (!scopeClaims.IsNullOrEmpty())
            {
                var scopeValues = scopeClaims.Select(x => x.Value).ToArray();

                if (options.EmitScopesAsSpaceDelimitedStringInJwt)
                {
                    payload.Add(JwtClaimTypes.Scope, string.Join(" ", scopeValues));
                }
                else
                {
                    payload.Add(JwtClaimTypes.Scope, scopeValues);
                }
            }

            // amr claims
            if (!amrClaims.IsNullOrEmpty())
            {
                var amrValues = amrClaims.Select(x => x.Value).Distinct().ToArray();
                payload.Add(JwtClaimTypes.AuthenticationMethod, amrValues);
            }
            
            // deal with json types
            // calling ToArray() to trigger JSON parsing once and so later 
            // collection identity comparisons work for the anonymous type
            try
            {
                var jsonTokens = jsonClaims.Select(x => new { x.Type, JsonValue = JRaw.Parse(x.Value) }).ToArray();

                // IdentityModel 7 uses System.Text.Json when writing JWT; JObject/JArray are not serialized correctly.
                // Convert to JsonElement for all JSON-valued claims (same fix as cnf claim).
                var jsonObjects = jsonTokens.Where(x => x.JsonValue.Type == JTokenType.Object).ToArray();
                var jsonObjectGroups = jsonObjects.GroupBy(x => x.Type).ToArray();
                foreach (var group in jsonObjectGroups)
                {
                    if (payload.ContainsKey(group.Key))
                    {
                        throw new Exception($"Can't add two claims where one is a JSON object and the other is not a JSON object ({group.Key})");
                    }

                    if (group.Skip(1).Any())
                    {
                        var elements = group.Select(x =>
                        {
                            var json = x.JsonValue.ToString();
                            return JsonSerializer.Deserialize<JsonElement>(json);
                        }).ToArray();
                        payload.Add(group.Key, elements);
                    }
                    else
                    {
                        var json = group.First().JsonValue.ToString();
                        payload.Add(group.Key, JsonSerializer.Deserialize<JsonElement>(json));
                    }
                }

                var jsonArrays = jsonTokens.Where(x => x.JsonValue.Type == JTokenType.Array).ToArray();
                var jsonArrayGroups = jsonArrays.GroupBy(x => x.Type).ToArray();
                foreach (var group in jsonArrayGroups)
                {
                    if (payload.ContainsKey(group.Key))
                    {
                        throw new Exception(
                            $"Can't add two claims where one is a JSON array and the other is not a JSON array ({group.Key})");
                    }

                    var newArr = new List<JsonElement>();
                    foreach (var arrays in group)
                    {
                        var arr = (JArray)arrays.JsonValue;
                        foreach (var item in arr)
                        {
                            newArr.Add(JsonSerializer.Deserialize<JsonElement>(item.ToString()));
                        }
                    }

                    payload.Add(group.Key, newArr.ToArray());
                }

                var unsupportedJsonTokens = jsonTokens.Except(jsonObjects).Except(jsonArrays).ToArray();
                var unsupportedJsonClaimTypes = unsupportedJsonTokens.Select(x => x.Type).Distinct().ToArray();
                if (unsupportedJsonClaimTypes.Any())
                {
                    throw new Exception(
                        $"Unsupported JSON type for claim types: {unsupportedJsonClaimTypes.Aggregate((x, y) => x + ", " + y)}");
                }

                return payload;
            }
            catch (Exception ex)
            {
                logger.LogCritical(ex, "Error creating a JSON valued claim");
                throw;
            }
        }
    }
}