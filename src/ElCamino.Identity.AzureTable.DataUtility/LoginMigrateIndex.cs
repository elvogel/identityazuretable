﻿// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.

using ElCamino.AspNetCore.Identity.AzureTable;
using ElCamino.AspNetCore.Identity.AzureTable.Model;
using Microsoft.Azure.Cosmos.Table;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ElCamino.Identity.AzureTable.DataUtility
{
    public class LoginMigrateIndex : IMigration
    {
        private readonly IKeyHelper _keyHelper;
        public LoginMigrateIndex(IKeyHelper keyHelper)
        {
            _keyHelper = keyHelper;
        }

        public TableQuery GetSourceTableQuery()
        {
            TableQuery tq = new TableQuery
            {
                SelectColumns = new List<string>() {"PartitionKey", "RowKey", "LoginProvider", "ProviderKey"}
            };
            string partitionFilter = TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.GreaterThanOrEqual, Constants.RowKeyConstants.PreFixIdentityUserId),
                TableOperators.And,
                TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.LessThan, "V_"));
            string rowFilter = TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition("RowKey", QueryComparisons.GreaterThanOrEqual, Constants.RowKeyConstants.PreFixIdentityUserLogin),
                TableOperators.And,
                TableQuery.GenerateFilterCondition("RowKey", QueryComparisons.LessThan, "M_"));
            tq.FilterString = TableQuery.CombineFilters(partitionFilter, TableOperators.And, rowFilter);
            return tq;
        }


        public bool UserWhereFilter(DynamicTableEntity d)
        {
            return !string.IsNullOrWhiteSpace(d.Properties["LoginProvider"].StringValue)
                && !string.IsNullOrWhiteSpace(d.Properties["ProviderKey"].StringValue);
        }

        public void ProcessMigrate(IdentityCloudContext targetContext,
            IdentityCloudContext sourceContext,
            IList<DynamicTableEntity> sourceUserResults,
            int maxDegreesParallel,
            Action updateComplete = null,
            Action<string> updateError = null)
        {
            var userIds = sourceUserResults
                .Where(UserWhereFilter)
                .Select(d => new
                {
                    UserId = d.PartitionKey,
                    LoginProvider = d.Properties["LoginProvider"].StringValue,
                    ProviderKey = d.Properties["ProviderKey"].StringValue
                })
                .ToList();


            Parallel.ForEach(userIds, new ParallelOptions() { MaxDegreeOfParallelism = maxDegreesParallel }, (userId) =>
            {

                //Add the email index
                try
                {
                    IdentityUserIndex index = CreateLoginIndex(userId.UserId, userId.LoginProvider, userId.ProviderKey);
                    var unused = targetContext.IndexTable.ExecuteAsync(TableOperation.InsertOrReplace(index)).Result;
                    updateComplete?.Invoke();
                }
                catch (Exception ex)
                {
                    updateError?.Invoke($"{userId.UserId}\t{ex.Message}");
                }

            });
        }

        private IdentityUserIndex CreateLoginIndex(string userid, string loginProvider, string providerKey)
        {
            return new IdentityUserIndex()
            {
                Id = userid,
                PartitionKey = _keyHelper.GeneratePartitionKeyIndexByLogin(loginProvider, providerKey),
                RowKey = _keyHelper.GenerateRowKeyIdentityUserLogin(loginProvider, providerKey),
                KeyVersion = _keyHelper.KeyVersion,
                ETag = Constants.ETagWildcard
            };

        }


    }
}
