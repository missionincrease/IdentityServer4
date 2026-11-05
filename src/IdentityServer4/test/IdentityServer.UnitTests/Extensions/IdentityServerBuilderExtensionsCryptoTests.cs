// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4;
using IdentityServer4.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;
using System.Security.Cryptography;
using Xunit;

namespace IdentityServer.UnitTests.Extensions
{
    public class IdentityServerBuilderExtensionsCryptoTests
    {
        // .NET 10 upgrade: Microsoft.IdentityModel.Tokens now uses System.Text.Json for JsonWebKey
        // deserialization, which rejects the previous hardcoded JSON (whitespace/format). Create the
        // JsonWebKey programmatically via JsonWebKeyConverter to avoid JSON parsing entirely.
        [Fact]
        public void AddSigningCredential_with_json_web_key_containing_asymmetric_key_should_succeed()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            using var rsa = RSA.Create(2048);
            var rsaKey = new RsaSecurityKey(rsa);
            var jsonWebKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaKey);
            jsonWebKey.Alg = SecurityAlgorithms.RsaSha256;

            SigningCredentials credentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
            identityServerBuilder.AddSigningCredential(credentials);
        }

        // .NET 10 upgrade: Same as asymmetric test - create JsonWebKey programmatically to avoid
        // JsonWebKey(string) deserialization which fails with System.Text.Json's stricter parsing.
        [Fact]
        public void AddSigningCredential_with_json_web_key_containing_symmetric_key_should_throw_exception()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            var keyBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(keyBytes);

            var jsonWebKey = new JsonWebKey
            {
                Kty = "oct",
                K = Base64UrlEncoder.Encode(keyBytes),
                Alg = SecurityAlgorithms.HmacSha256,
                Use = "sig"
            };

            SigningCredentials credentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
            Assert.Throws<InvalidOperationException>(() => identityServerBuilder.AddSigningCredential(credentials));
        }

        [Fact]
        public void AddDeveloperSigningCredential_should_succeed()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            identityServerBuilder.AddDeveloperSigningCredential();

            //clean up... delete stored rsa key
            var filename = Path.Combine(Directory.GetCurrentDirectory(), "tempkey.rsa");

            if (File.Exists(filename))
                File.Delete(filename);
        }

        [Fact]
        public void AddDeveloperSigningCredential_should_succeed_when_called_multiple_times()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            try
            {
                identityServerBuilder.AddDeveloperSigningCredential();

                //calling a second time will try to load the saved rsa key from disk. An exception will be throw if the private key is not serialized properly.
                identityServerBuilder.AddDeveloperSigningCredential();
            }
            finally
            {
                //clean up... delete stored rsa key
                var filename = Path.Combine(Directory.GetCurrentDirectory(), "tempkey.rsa");

                if (File.Exists(filename))
                    File.Delete(filename);
            }
        }

        [Theory]
        [InlineData(Constants.CurveOids.P256, SecurityAlgorithms.EcdsaSha256)]
        [InlineData(Constants.CurveOids.P384, SecurityAlgorithms.EcdsaSha384)]
        [InlineData(Constants.CurveOids.P521, SecurityAlgorithms.EcdsaSha512)]
        public void AddSigningCredential_with_valid_curve_should_succeed(string curveOid, string alg)
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            var key = new ECDsaSecurityKey(ECDsa.Create(
                ECCurve.CreateFromOid(Oid.FromOidValue(curveOid, OidGroup.All))));

            identityServerBuilder.AddSigningCredential(key, alg);
        }

        [Theory]
        [InlineData(Constants.CurveOids.P256, SecurityAlgorithms.EcdsaSha512)]
        [InlineData(Constants.CurveOids.P384, SecurityAlgorithms.EcdsaSha512)]
        [InlineData(Constants.CurveOids.P521, SecurityAlgorithms.EcdsaSha256)]
        public void AddSigningCredential_with_invalid_curve_should_throw_exception(string curveOid, string alg)
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            var key = new ECDsaSecurityKey(ECDsa.Create(
                ECCurve.CreateFromOid(Oid.FromOidValue(curveOid, OidGroup.All))));

            Assert.Throws<InvalidOperationException>(() => identityServerBuilder.AddSigningCredential(key, alg));
        }



        [Theory]
        [InlineData(Constants.CurveOids.P256, SecurityAlgorithms.EcdsaSha256, JsonWebKeyECTypes.P256)]
        [InlineData(Constants.CurveOids.P384, SecurityAlgorithms.EcdsaSha384, JsonWebKeyECTypes.P384)]
        [InlineData(Constants.CurveOids.P521, SecurityAlgorithms.EcdsaSha512, JsonWebKeyECTypes.P521)]
        public void AddSigningCredential_with_invalid_crv_value_should_throw_exception(string curveOid, string alg, string crv)
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            var key = new ECDsaSecurityKey(ECDsa.Create(
                ECCurve.CreateFromOid(Oid.FromOidValue(curveOid, OidGroup.All))));
            var parameters = key.ECDsa.ExportParameters(true);

            var jsonWebKeyFromECDsa = new JsonWebKey()
            {
                Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                Use = "sig",
                Kid = key.KeyId,
                KeyId = key.KeyId,
                X = Base64UrlEncoder.Encode(parameters.Q.X),
                Y = Base64UrlEncoder.Encode(parameters.Q.Y),
                D = Base64UrlEncoder.Encode(parameters.D),
                Crv = crv.Replace("-", string.Empty),
                Alg = SecurityAlgorithms.EcdsaSha256
            };
            Assert.Throws<InvalidOperationException>(() => identityServerBuilder.AddSigningCredential(jsonWebKeyFromECDsa, alg));
        }
    }
}
