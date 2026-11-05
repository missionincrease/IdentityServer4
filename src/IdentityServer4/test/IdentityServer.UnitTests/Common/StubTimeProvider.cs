// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading;

namespace IdentityServer.UnitTests.Common
{
    internal class StubTimeProvider : TimeProvider
    {
        public Func<DateTimeOffset> UtcNowFunc = () => DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => UtcNowFunc();

        public override TimeZoneInfo LocalTimeZone => TimeZoneInfo.Utc;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            base.CreateTimer(callback, state, dueTime, period);
    }
}
