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
    public class EmailMigrateIndex : IMigration
    {
        private readonly IKeyHelper _keyHelper;
        public EmailMigrateIndex(IKeyHelper keyHelper)
        {
            _keyHelper = keyHelper;
        }

        public TableQuery GetSourceTableQuery()
        {
            var tq = new TableQuery {SelectColumns = new List<string>() {"PartitionKey", "RowKey", "Email"}};
            var partitionFilter = TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.GreaterThanOrEqual, Constants.RowKeyConstants.PreFixIdentityUserId),
                TableOperators.And,
                TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.LessThan, "V_"));
            var rowFilter = TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition("RowKey", QueryComparisons.GreaterThanOrEqual, Constants.RowKeyConstants.PreFixIdentityUserId),
                TableOperators.And,
                TableQuery.GenerateFilterCondition("RowKey", QueryComparisons.LessThan, "V_"));
            tq.FilterString = TableQuery.CombineFilters(partitionFilter, TableOperators.And, rowFilter);
            return tq;
        }


        public bool UserWhereFilter(DynamicTableEntity d)
        {
            return !string.IsNullOrWhiteSpace(d.Properties["Email"].StringValue);
        }

        public void ProcessMigrate(IdentityCloudContext targetContext,
            IdentityCloudContext sourceContext,
            IList<DynamicTableEntity> userResults,
            int maxDegreesParallel,
            Action updateComplete = null,
            Action<string> updateError = null)
        {
            var userIds = userResults
                .Where(UserWhereFilter)
                .Select(d => new { UserId = d.PartitionKey, Email = d.Properties["Email"].StringValue })
                .ToList();


            Parallel.ForEach(userIds, new ParallelOptions() { MaxDegreeOfParallelism = maxDegreesParallel }, (userId) =>
            {

                //Add the email index
                try
                {
                    IdentityUserIndex index = CreateEmailIndex(userId.UserId, userId.Email);
                    var unused = targetContext.IndexTable.ExecuteAsync(TableOperation.InsertOrReplace(index)).Result;
                    updateComplete?.Invoke();
                }
                catch (Exception ex)
                {
                    updateError?.Invoke($"{userId.UserId}\t{ex.Message}");
                }

            });
        }

        /// <summary>
        /// Creates an email index suitable for a crud operation
        /// </summary>
        /// <param name="userid">Formatted UserId from the KeyHelper or IdentityUser.Id.ToString()</param>
        /// <param name="email">Plain email address.</param>
        /// <returns></returns>
        private IdentityUserIndex CreateEmailIndex(string userid, string email)
        {
            return new IdentityUserIndex()
            {
                Id = userid,
                PartitionKey = _keyHelper.GenerateRowKeyUserEmail(email),
                RowKey = userid,
                KeyVersion = _keyHelper.KeyVersion,
                ETag = Constants.ETagWildcard
            };
        }

    }
}
