// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityServer.IntegrationTests.Common;
using IdentityServer4.Models;
using IdentityServer4.Test;
using Xunit;

namespace IdentityServer.IntegrationTests.Conformance.Basic
{
    public class ResponseTypeResponseModeTests
    {
        private const string Category = "Conformance.Basic.ResponseTypeResponseModeTests";

        private IdentityServerPipeline _mockPipeline = new IdentityServerPipeline();

        public ResponseTypeResponseModeTests()
        {
            _mockPipeline.Initialize();
            _mockPipeline.BrowserClient.AllowAutoRedirect = false;
            _mockPipeline.Clients.Add(new Client
            {
                Enabled = true,
                ClientId = "code_client",
                ClientSecrets = new List<Secret>
                {
                    new Secret("secret".Sha512())
                },

                AllowedGrantTypes = GrantTypes.Code,
                AllowedScopes = { "openid" },

                RequireConsent = false,
                RequirePkce = false,
                RedirectUris = new List<string>
                {
                    "https://code_client/callback"
                }
            });

            _mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());

            _mockPipeline.Users.Add(new TestUser
            {
                SubjectId = "bob",
                Username = "bob",
                Claims = new Claim[]
                    {
                        new Claim("name", "Bob Loblaw"),
                        new Claim("email", "bob@loblaw.com"),
                        new Claim("role", "Attorney")
                    }
            });
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Request_with_response_type_code_supported()
        {
            await _mockPipeline.LoginAsync("bob");

            var metadata = await _mockPipeline.BackChannelClient.GetAsync(IdentityServerPipeline.DiscoveryEndpoint);
            metadata.StatusCode.Should().Be(HttpStatusCode.OK);

            var state = Guid.NewGuid().ToString();
            var nonce = Guid.NewGuid().ToString();

            var url = _mockPipeline.CreateAuthorizeUrl(
                           clientId: "code_client",
                           responseType: "code",
                           scope: "openid",
                           redirectUri: "https://code_client/callback",
                           state: state,
                           nonce: nonce);
            var response = await _mockPipeline.BrowserClient.GetAsync(url);
            response.StatusCode.Should().Be(HttpStatusCode.Found);

            var authorization = new IdentityModel.Client.AuthorizeResponse(response.Headers.Location.ToString());
            authorization.IsError.Should().BeFalse();
            authorization.Code.Should().NotBeNull();
            authorization.State.Should().Be(state);
        }

        // this might not be in sync with the actual conformance tests
        // since we dead-end on the error page due to changes 
        // to follow the RFC to address open redirect in original OAuth RFC
        [Fact]
        [Trait("Category", Category)]
        public async Task Request_missing_response_type_rejected()
        {
            await _mockPipeline.LoginAsync("bob");

            var state = Guid.NewGuid().ToString();
            var nonce = Guid.NewGuid().ToString();

            // .NET 10 / IdentityModel 7 upgrade fix:
            // IdentityModel 7's RequestUrlExtensions.CreateAuthorizeUrl now requires response_type
            // and throws ArgumentException if null/empty. We need to test that the server (IdentityServer4)
            // correctly rejects requests missing response_type. Build the URL manually here so we can
            // omit response_type and verify server returns "unsupported_response_type".
            var queryParams = new Dictionary<string, string>
            {
                { "client_id", "code_client" },
                { "scope", "openid" },
                { "redirect_uri", "https://code_client/callback" },
                { "state", state },
                { "nonce", nonce }
            };
            var query = string.Join("&", queryParams.Select(kv => $"{kv.Key}={Uri.EscapeDataString(kv.Value)}"));
            var url = IdentityServerPipeline.AuthorizeEndpoint + "?" + query;

            _mockPipeline.BrowserClient.AllowAutoRedirect = true;
            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            _mockPipeline.ErrorMessage.Error.Should().Be("unsupported_response_type");
        }
    }
}
