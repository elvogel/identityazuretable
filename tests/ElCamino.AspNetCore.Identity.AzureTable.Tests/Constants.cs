﻿// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.

using System;

namespace ElCamino.AspNetCore.Identity.AzureTable.Tests
{
    public static class Constants
    {
        // e.g. http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
        public const string ClaimTypeNamespace = "http://schemas.test.com/ws/2014/01/identity/claims/";

        /// <summary>
        /// Claims will contain Test identifiers for the respective operation
        /// </summary>
        public static class AccountClaimTypes
        {
            public const string AccountTestAdminClaim = ClaimTypeNamespace + "AccountTestAdminClaim";
            public const string AccountTestUserClaim = ClaimTypeNamespace + "AccountTestUserClaim";

        }

        public static class AccountRoles
        {
            public const string AccountTestAdminRole =  "AccountTestAdminRole";
            public const string AccountTestUserRole = "AccountTestUserRole";
        }

        public static class LoginProviders
        {
            public static class GoogleProvider
            {
                public const string LoginProvider = "Google";
                public static string ProviderKey =>
                    $"https://www.google.com/accounts/o8/id?id={Guid.NewGuid():N}";
            }
        }
    }
}
