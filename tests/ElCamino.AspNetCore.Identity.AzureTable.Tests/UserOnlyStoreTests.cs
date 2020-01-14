﻿// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Xunit;
using Xunit.Abstractions;
using ElCamino.AspNetCore.Identity.AzureTable;
using IdentityUser = ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityUser<string>;
using IdentityRole = ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole;
using ElCamino.Web.Identity.AzureTable.Tests.ModelTests;
using ElCamino.Web.Identity.AzureTable.Tests.Fixtures;
using Microsoft.AspNetCore.Identity;

namespace ElCamino.AspNetCore.Identity.AzureTable.Tests
{
    public partial class UserOnlyStoreTests : BaseUserStoreTests<ApplicationUserV2, IdentityCloudContext, UserOnlyStore<ApplicationUserV2, IdentityCloudContext>>
    {
        public const string UserOnlyStoreTrait = "IdentityCore.Azure.UserOnlyStore";
        public UserOnlyStoreTests(UserFixture<ApplicationUserV2, IdentityCloudContext, UserOnlyStore<ApplicationUserV2, IdentityCloudContext>> userFix, ITestOutputHelper output) :
            base(userFix, output) {  }
        [Fact(DisplayName = "AddRemoveUserClaim")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task AddRemoveUserClaim()
        {
            return base.AddRemoveUserClaim();
        }

        [Fact(DisplayName = "AddRemoveUserLogin")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task AddRemoveUserLogin()
        {
            return base.AddRemoveUserLogin();
        }

        [Fact(DisplayName = "AddRemoveUserToken")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task AddRemoveUserToken()
        {
            return base.AddRemoveUserToken();
        }

        [Fact(DisplayName = "AddReplaceRemoveUserClaim")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task AddReplaceRemoveUserClaim()
        {
            return base.AddReplaceRemoveUserClaim();
        }

        [Fact(DisplayName = "AddUserClaim")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task AddUserClaim()
        {
            return base.AddUserClaim();
        }

        [Fact(DisplayName = "AddUserLogin")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task AddUserLogin()
        {
            return base.AddUserLogin();
        }

        [Fact(DisplayName = "ChangeUserName")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task ChangeUserName()
        {
            return base.ChangeUserName();
        }

        [Fact(DisplayName = "CheckDupEmail")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task CheckDupEmail()
        {
            return base.CheckDupEmail();
        }

        [Trait(UserOnlyStoreTrait, "")]
        [Fact(DisplayName = "CheckDupUser")]
        public override Task CheckDupUser()
        {
            return base.CheckDupUser();
        }

        [Fact(DisplayName = "CreateUser")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task CreateUserTest()
        {
            return base.CreateUserTest();
        }

        [Fact(DisplayName = "DeleteUser")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task DeleteUser()
        {
            return base.DeleteUser();
        }

        [Fact(DisplayName = "FindUserByEmail")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task FindUserByEmail()
        {
            return base.FindUserByEmail();
        }

        [Fact(DisplayName = "FindUserById")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task FindUserById()
        {
            return base.FindUserById();
        }

        [Fact(DisplayName = "FindUserByName")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task FindUserByName()
        {
            return base.FindUserByName();
        }

        [Fact(DisplayName = "FindUsersByEmail")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task FindUsersByEmail()
        {
            return base.FindUsersByEmail();
        }

        [Fact(DisplayName = "GetUsersByClaim")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task GetUsersByClaim()
        {
            return base.GetUsersByClaim();
        }

        [Fact(DisplayName = "ThrowIfDisposed")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task ThrowIfDisposed()
        {
            return base.ThrowIfDisposed();
        }

        [Fact(DisplayName = "UpdateApplicationUser")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task UpdateApplicationUser()
        {
            return base.UpdateApplicationUser();
        }

        [Fact(DisplayName = "UpdateUser")]
        [Trait(UserOnlyStoreTrait, "")]
        public override Task UpdateUser()
        {
            return base.UpdateUser();
        }

        [Fact(DisplayName = "UserStoreCtors")]
        [Trait(UserOnlyStoreTrait, "")]
        public override void UserStoreCtors()
        {
            Assert.Throws<ArgumentNullException>(() => 
            {
                new UserOnlyStore<ApplicationUserV2, IdentityCloudContext>(null, null, null);
            });
        }
    }

}